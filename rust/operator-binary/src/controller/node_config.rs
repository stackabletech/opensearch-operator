use super::ValidatedCluster;
use crate::{
    crd::{NodeRoles, v1alpha1},
    framework::{RoleName, to_qualified_role_group_name},
};

pub const DISCOVERY_SEED_HOSTS: &str = "discovery.seed_hosts";
pub const DISCOVERY_TYPE: &str = "discovery.type";
pub const INITIAL_CLUSTER_MANAGER_NODES: &str = "cluster.initial_cluster_manager_nodes";
pub const NETWORK_HOST: &str = "network.host";
pub const NODE_NAME: &str = "node.name";
pub const NODE_ROLES: &str = "node.roles";

pub struct NodeConfig {
    role_name: RoleName,
    cluster: ValidatedCluster,
}

impl NodeConfig {
    pub fn new(role_name: RoleName, cluster: ValidatedCluster) -> Self {
        Self { role_name, cluster }
    }

    pub fn discovery_seed_hosts(&self) -> String {
        // TODO Fix
        format!("{}-cluster-manager", self.cluster.name)
    }

    /// Configuration for `{DISCOVERY_TYPE}`
    ///
    /// "zen" is the default if `{DISCOVERY_TYPE}` is not set.
    /// It is nevertheless explicitly set here.
    /// see https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/discovery/DiscoveryModule.java#L88-L89
    pub fn discovery_type(&self) -> String {
        if self.cluster.is_single_node() {
            "single-node".to_owned()
        } else {
            "zen".to_owned()
        }
    }

    /// Configuration for `cluster.initial_cluster_manager_nodes` which replaces
    /// `cluster.initial_master_nodes`, see
    /// https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/coordination/ClusterBootstrapService.java#L79-L93.
    ///
    /// According to
    /// https://docs.opensearch.org/docs/3.0/install-and-configure/configuring-opensearch/discovery-gateway-settings/,
    /// it contains "a list of cluster-manager-eligible nodes used to bootstrap the cluster."
    ///
    /// However, the documentation for Elasticsearch is more detailed and contains the following
    /// notes (see https://www.elastic.co/guide/en/elasticsearch/reference/9.0/modules-discovery-settings.html):
    /// * Remove this setting once the cluster has formed, and never set it again for this cluster.
    /// * Do not configure this setting on master-ineligible nodes.
    /// * Do not configure this setting on nodes joining an existing cluster.
    /// * Do not configure this setting on nodes which are restarting.
    /// * Do not configure this setting when performing a full-cluster restart.
    ///
    /// The OpenSearch Helm chart only sets master nodes but does not handle the other cases (see
    /// https://github.com/opensearch-project/helm-charts/blob/opensearch-3.0.0/charts/opensearch/templates/statefulset.yaml#L414-L415),
    /// so they are also ignored here for the moment.
    pub fn initial_cluster_manager_nodes(&self, node_roles: &NodeRoles) -> String {
        if !self.cluster.is_single_node()
            && node_roles.contains(&v1alpha1::NodeRole::ClusterManager)
        {
            let cluster_manager_configs = self
                .cluster
                .role_group_configs_filtered_by_node_role(&v1alpha1::NodeRole::ClusterManager);

            // This setting requires node names as set in `{NODE_NAME}`.
            // The node names are set to the pod names with
            // `valueFrom.fieldRef.fieldPath: metadata.name`, so it is okay to calculate the pod
            // names here and use them as node names.
            let mut pod_names = vec![];
            for (role_group_name, role_group_config) in cluster_manager_configs {
                let sts_name = to_qualified_role_group_name(
                    &self.cluster.name,
                    &self.role_name,
                    &role_group_name,
                );
                pod_names.extend(
                    (0..role_group_config.replicas.unwrap_or(1)).map(|i| format!("{sts_name}-{i}")),
                );
            }
            pod_names.join(",")
        } else {
            // This setting is not allowed on single node cluster, see
            // https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/coordination/ClusterBootstrapService.java#L126-L136
            String::new()
        }
    }

    pub fn network_host(&self) -> String {
        "0.0.0.0".to_owned()
    }

    pub fn node_roles(&self, node_roles: &NodeRoles) -> String {
        node_roles
            .iter()
            .map(|r| format!("{}", r))
            .collect::<Vec<_>>()
            .join(",")
    }
}
