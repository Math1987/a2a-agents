//! Exercise the production DynamoStore through the official AWS SDK's HTTP
//! serialization and error decoding. Only DynamoDB's HTTP endpoint is replaced;
//! no AWS credentials, account, table or network service is used by these tests.
use a2a_agents::store::{DynamoStore, MemoryStore, Row, Store};
use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region, retry::RetryConfig};
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::header};

fn store(server: &MockServer, table: &str) -> DynamoStore {
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("eu-west-1"))
        .credentials_provider(Credentials::new("test", "test", None, None, "test"))
        .endpoint_url(server.uri())
        .retry_config(RetryConfig::disabled())
        .build();
    DynamoStore::new(aws_sdk_dynamodb::Client::from_conf(config), table.into())
}

fn response(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "application/x-amz-json-1.0")
        .set_body_json(body)
}

fn item(number: usize) -> Value {
    json!({
        "pk":{"S":format!("AGENT#{number:03}")},
        "sk":{"S":format!("CONN#{number:03}")},
        "version":{"N":"7"},
        "payload":{"S":json!({"number":number,"status":"connected"}).to_string()},
        "maintenance_pk":{"S":"CONNECTION"},
        "maintenance_due":{"N":(1000+number).to_string()},
    })
}

#[tokio::test]
async fn conditional_put_serializes_versions_ttl_and_index_and_propagates_non_conflicts() {
    let server = MockServer::start().await;
    Mock::given(header("x-amz-target", "DynamoDB_20120810.PutItem"))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            match body["Item"]["pk"]["S"].as_str().unwrap() {
                "conflict" => response(400, json!({"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException", "message":"version changed"})),
                "invalid" => response(400, json!({"__type":"com.amazonaws.dynamodb.v20120810#ValidationException", "message":"invalid write"})),
                _ => response(200, json!({})),
            }
        })
        .expect(4)
        .mount(&server)
        .await;
    let db = store(&server, "agents-test");
    let mut row = Row::new("AGENT#one", "OAUTH#state", json!({"encrypted":"opaque"}));
    row.expires_at = Some(1600);
    row.due = Some(("CONNECTION".into(), 1500));
    assert!(db.put(row.clone(), None).await.unwrap());
    row.version = 999; // Expected CAS version, not this caller field, is authoritative.
    row.expires_at = None;
    row.due = None;
    assert!(db.put(row, Some(7)).await.unwrap());
    assert!(
        !db.put(Row::new("conflict", "META", json!({})), Some(1))
            .await
            .unwrap()
    );
    assert!(
        db.put(Row::new("invalid", "META", json!({})), Some(1))
            .await
            .is_err()
    );

    let requests = server.received_requests().await.unwrap();
    let create: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(create["TableName"], "agents-test");
    assert_eq!(create["ConditionExpression"], "attribute_not_exists(pk)");
    assert_eq!(create["Item"]["version"], json!({"N":"1"}));
    assert_eq!(create["Item"]["expires_at"], json!({"N":"1600"}));
    assert_eq!(create["Item"]["maintenance_pk"], json!({"S":"CONNECTION"}));
    assert_eq!(create["Item"]["maintenance_due"], json!({"N":"1500"}));
    assert_eq!(
        serde_json::from_str::<Value>(create["Item"]["payload"]["S"].as_str().unwrap()).unwrap(),
        json!({"encrypted":"opaque"})
    );
    let update: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(update["ConditionExpression"], "#v = :v");
    assert_eq!(update["ExpressionAttributeNames"]["#v"], "version");
    assert_eq!(update["ExpressionAttributeValues"][":v"], json!({"N":"7"}));
    assert_eq!(update["Item"]["version"], json!({"N":"8"}));
    // PutItem replaces the full record: omitting these attributes removes stale
    // temporary-state expiry and maintenance-index membership, rather than
    // unintentionally attaching OAuth state TTL to durable credentials.
    assert!(update["Item"].get("expires_at").is_none());
    assert!(update["Item"].get("maintenance_pk").is_none());
    assert!(update["Item"].get("maintenance_due").is_none());
}

#[tokio::test]
async fn get_uses_consistent_read_and_decodes_durable_payload_and_optional_indexes() {
    let server = MockServer::start().await;
    Mock::given(header("x-amz-target", "DynamoDB_20120810.GetItem"))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            if body["Key"]["pk"]["S"] == "missing" {
                response(200, json!({}))
            } else {
                let mut data = item(2);
                data["expires_at"] = json!({"N":"1800"});
                response(200, json!({"Item":data}))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let db = store(&server, "agents-test");
    let row = db.get("AGENT#002", "CONN#002").await.unwrap().unwrap();
    assert_eq!(row.pk, "AGENT#002");
    assert_eq!(row.sk, "CONN#002");
    assert_eq!(row.version, 7);
    assert_eq!(row.payload["number"], 2);
    assert_eq!(row.expires_at, Some(1800));
    assert_eq!(row.due, Some(("CONNECTION".into(), 1002)));
    assert!(db.get("missing", "META").await.unwrap().is_none());
    for request in server.received_requests().await.unwrap() {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["ConsistentRead"], true);
        assert_eq!(body["TableName"], "agents-test");
    }
}

#[tokio::test]
async fn transaction_keeps_all_conditional_writes_ttl_and_index_in_one_sdk_request() {
    let server = MockServer::start().await;
    Mock::given(header(
        "x-amz-target",
        "DynamoDB_20120810.TransactWriteItems",
    ))
    .respond_with(response(200, json!({})))
    .expect(1)
    .mount(&server)
    .await;
    let db = store(&server, "agents-test");
    let credentials = Row::new(
        "AGENT#one",
        "CREDENTIALS#connection",
        json!({"sealed":"opaque"}),
    );
    let mut lease = Row::new("AGENT#one", "LOCK#connection", json!({"until":0}));
    lease.expires_at = Some(1234);
    lease.due = Some(("CONNECTION".into(), 1200));
    assert!(
        db.transaction(vec![(credentials, None), (lease, Some(9))])
            .await
            .unwrap()
    );
    let requests = server.received_requests().await.unwrap();
    let request: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let writes = request["TransactItems"].as_array().unwrap();
    assert_eq!(writes.len(), 2);
    assert_eq!(
        writes[0]["Put"]["ConditionExpression"],
        "attribute_not_exists(pk)"
    );
    assert_eq!(writes[0]["Put"]["Item"]["version"], json!({"N":"1"}));
    assert!(writes[0]["Put"]["Item"].get("expires_at").is_none());
    assert_eq!(writes[1]["Put"]["ConditionExpression"], "#v = :v");
    assert_eq!(
        writes[1]["Put"]["ExpressionAttributeValues"][":v"],
        json!({"N":"9"})
    );
    assert_eq!(writes[1]["Put"]["Item"]["version"], json!({"N":"10"}));
    assert_eq!(writes[1]["Put"]["Item"]["expires_at"], json!({"N":"1234"}));
    assert_eq!(
        writes[1]["Put"]["Item"]["maintenance_due"],
        json!({"N":"1200"})
    );
}

#[tokio::test]
async fn transaction_cancellation_only_maps_actual_concurrency_conflicts_to_false() {
    let server = MockServer::start().await;
    Mock::given(header(
        "x-amz-target",
        "DynamoDB_20120810.TransactWriteItems",
    ))
    .respond_with(|request: &Request| {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let reasons = match body["TransactItems"][0]["Put"]["TableName"]
            .as_str()
            .unwrap()
        {
            "conditional" => json!([{"Code":"None"},{"Code":"ConditionalCheckFailed"}]),
            "transaction-conflict" => json!([{"Code":"TransactionConflict"}]),
            "validation" => json!([{"Code":"ValidationError","Message":"invalid expression"}]),
            "mixed" => json!([{"Code":"ConditionalCheckFailed"},{"Code":"ValidationError"}]),
            "throughput" => json!([{"Code":"ProvisionedThroughputExceeded"}]),
            "missing-reasons" => json!([]),
            other => panic!("unexpected fixture table {other}"),
        };
        response(
            400,
            json!({"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException",
                "message":"transaction cancelled", "CancellationReasons":reasons}),
        )
    })
    .expect(6)
    .mount(&server)
    .await;
    for (table, conflict) in [
        ("conditional", true),
        ("transaction-conflict", true),
        ("validation", false),
        ("mixed", false),
        ("throughput", false),
        ("missing-reasons", false),
    ] {
        let result = store(&server, table)
            .transaction(vec![(
                Row::new("budget", "month", json!({"reserved":1})),
                Some(1),
            )])
            .await;
        if conflict {
            assert!(!result.unwrap(), "{table}");
        } else {
            assert!(
                result.is_err(),
                "{table} must not be mistaken for exhausted budget or contention"
            );
        }
    }
}

#[tokio::test]
async fn due_follows_a_short_dynamodb_page_then_stops_at_one_hundred_rows() {
    let server = MockServer::start().await;
    let cursor = json!({"pk":{"S":"AGENT#001"},"sk":{"S":"CONN#001"},
        "maintenance_pk":{"S":"CONNECTION"},"maintenance_due":{"N":"1001"}});
    let expected_cursor = cursor.clone();
    Mock::given(header("x-amz-target", "DynamoDB_20120810.Query"))
        .respond_with(move |request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["IndexName"],"maintenance-index");
            assert_eq!(body["KeyConditionExpression"],"maintenance_pk = :kind AND maintenance_due <= :now");
            assert_eq!(body["ExpressionAttributeValues"][":kind"],json!({"S":"CONNECTION"}));
            assert_eq!(body["ExpressionAttributeValues"][":now"],json!({"N":"2000"}));
            // Global secondary indexes do not support strongly consistent reads.
            assert_ne!(body["ConsistentRead"],true);
            if body.get("ExclusiveStartKey").is_none() {
                assert_eq!(body["Limit"],100);
                // Simulates the 1 MiB response limit being reached before Limit.
                response(200,json!({"Items":[item(0),item(1)],"LastEvaluatedKey":cursor}))
            } else {
                assert_eq!(body["ExclusiveStartKey"],expected_cursor);
                assert_eq!(body["Limit"],98);
                let items:Vec<_>=(2..100).map(item).collect();
                response(200,json!({"Items":items,"LastEvaluatedKey":{"pk":{"S":"AGENT#099"},"sk":{"S":"CONN#099"}}}))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let rows = store(&server, "agents-test")
        .due("CONNECTION", 2000)
        .await
        .unwrap();
    assert_eq!(rows.len(), 100);
    assert_eq!(rows.first().unwrap().payload["number"], 0);
    assert_eq!(rows.last().unwrap().payload["number"], 99);
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn memory_due_matches_index_time_order_and_hundred_item_cap() {
    let db = MemoryStore::default();
    for number in 0..101 {
        let mut row = Row::new(
            format!("AGENT#{number:03}"),
            "TASK#one",
            json!({"number":number}),
        );
        row.due = Some(("TASK".into(), 1000 - number));
        assert!(db.put(row, None).await.unwrap());
    }
    let rows = db.due("TASK", 2000).await.unwrap();
    assert_eq!(rows.len(), 100);
    assert_eq!(rows[0].payload["number"], 100);
    assert_eq!(rows[99].payload["number"], 1);
    assert!(db.due("CONNECTION", 2000).await.unwrap().is_empty());
}
