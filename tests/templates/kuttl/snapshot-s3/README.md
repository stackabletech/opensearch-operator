1. Create an OpenSearch cluster
2. Create a test user via the security API
3. The test user creates an index and adds data
4. Create a backup of the security index and a snapshot of all other indexes
5. Delete the OpenSearch cluster
6. Create another OpenSearch cluster
7. Restore the security index and the snapshot
8. Test that the test user can read its data
