use super::*;

impl VeilidAPI {
    /// The debug commands a mocked node supports.
    ///
    /// The real command set reaches into subsystems mock-api compiles out, so only the commands
    /// tests drive are served here. Anything else says so instead of returning nothing.
    pub async fn debug(&self, args: String) -> VeilidAPIResult<String> {
        let args = args.trim();
        let words: Vec<&str> = args.split_whitespace().collect();

        match words.as_slice() {
            [] | ["help"] => Ok(MOCK_DEBUG_HELP.to_owned()),
            // Purging the local record store leaves the records on their storage nodes
            ["record", "purge", "local"] => {
                let count = MockNetwork::with_node(&self.mock_key()?, |node| {
                    let count = node.opened_records.len();
                    node.opened_records.clear();
                    count
                })?;
                Ok(format!("purged {} local records", count))
            }
            // A mock node stores nothing for anyone else, so its remote record store is empty
            ["record", "purge", "remote"] => {
                MockNetwork::with_node(&self.mock_key()?, |node| {
                    node.opened_records.clear();
                })?;
                Ok("purged 0 remote records".to_owned())
            }
            ["record", "list"] => {
                let keys = with_records(|records| {
                    records.keys().map(|k| k.to_string()).collect::<Vec<_>>()
                });
                Ok(format!("{} records:\n{}", keys.len(), keys.join("\n")))
            }
            ["nodeid"] => {
                let node_ids = MockNetwork::with_node(&self.mock_key()?, |node| {
                    node.node_ids
                        .iter()
                        .map(|id| id.to_string())
                        .collect::<Vec<_>>()
                })?;
                Ok(node_ids.join(" "))
            }
            _ => Ok(format!(
                "unsupported under mock-api: '{}'\n\n{}",
                args, MOCK_DEBUG_HELP
            )),
        }
    }
}

const MOCK_DEBUG_HELP: &str = "\
mock-api debug commands:
    record purge local      close every record and drop this node's copies
    record purge remote     no-op: a mock node holds no records for others
    record list             list the mock network's records
    nodeid                  show this node's ids";
