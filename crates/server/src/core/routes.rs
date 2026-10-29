//! Per-direction route policies and which networks a user may use.
use super::{Caller, Core};
use netbridge_proto::*;

const KEY: &str = "route_policies";

impl Core {
    fn stored_route_policies(&self) -> Result<Vec<RoutePolicy>, ApiError> {
        Ok(self.db.setting(KEY)?.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default())
    }

    /// One policy per topology route as the admin set it (`None` fields follow the global policy).
    pub fn route_policies(&self) -> Result<Vec<RoutePolicy>, ApiError> {
        let stored = self.stored_route_policies()?;
        Ok(self.topo.routes.iter().map(|r| stored.iter().find(|p| p.route == *r).cloned().unwrap_or_else(|| RoutePolicy::new(r.clone()))).collect())
    }

    /// The route's policy with inherited fields filled in from the global policy.
    pub fn route_policy(&self, route: &Route) -> Result<RoutePolicy, ApiError> {
        if !self.topo.has_route(route) {
            return Err(ApiError::new(ErrorCode::Forbidden, format!("허용되지 않은 통로입니다: {}", route.label(&self.topo))));
        }
        let p = self.route_policies()?.into_iter().find(|p| p.route == *route).expect("topology route");
        Ok(p.resolved(&self.db.policy()?))
    }

    pub fn set_route_policy(&self, p: &RoutePolicy) -> Result<(), ApiError> {
        if !self.topo.has_route(&p.route) {
            return Err(ApiError::bad(format!("설정에 없는 통로입니다: {}", p.route.label(&self.topo))));
        }
        let mut all = self.route_policies()?;
        for x in all.iter_mut() {
            if x.route == p.route {
                *x = p.clone();
            }
        }
        self.db.set_setting(KEY, &serde_json::to_string(&all).map_err(ApiError::internal)?)
    }

    /// 0.1–0.3 kept one global list of approval rules with an optional direction; copy them onto the routes once.
    pub(super) fn migrate_route_policies(&self) -> Result<(), ApiError> {
        if self.db.setting(KEY)?.is_some() {
            return Ok(());
        }
        let legacy: Vec<serde_json::Value> = self.db.setting("approval_rules")?.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let mut out = vec![];
        for r in &self.topo.routes {
            let mut p = RoutePolicy::new(r.clone());
            for v in &legacy {
                let dir = v.get("direction").and_then(|d| d.as_str());
                let applies = match dir {
                    None => true,
                    Some("ToInternal") => *r == Route::new(NetId::external(), NetId::internal()),
                    Some("ToExternal") => *r == Route::new(NetId::internal(), NetId::external()),
                    Some(_) => false,
                };
                if applies {
                    if let Ok(rule) = serde_json::from_value::<ApprovalRule>(v.clone()) {
                        p.approval_rules.push(rule);
                    }
                }
            }
            out.push(p);
        }
        self.db.set_setting(KEY, &serde_json::to_string(&out).map_err(ApiError::internal)?)
    }

    /// Networks the user may use; an empty list in the database means all of them.
    pub fn user_networks(&self, user_id: i64) -> Result<Vec<NetId>, ApiError> {
        let raw: String = self.db.with(|c| c.query_row("SELECT networks FROM users WHERE id=?1", [user_id], |r| r.get(0)))?;
        let mine: Vec<NetId> = serde_json::from_str(&raw).unwrap_or_default();
        Ok(if mine.is_empty() { self.topo.networks.iter().map(|n| n.id.clone()).collect() } else { mine })
    }

    /// The route from the caller's network to `to`, if it exists, is enabled and the user may use `to`.
    pub fn user_route(&self, c: &Caller, to: &NetId) -> Result<RoutePolicy, ApiError> {
        let route = Route::new(c.side.clone(), to.clone());
        let p = self.route_policy(&route)?;
        if !p.enabled {
            return Err(ApiError::new(ErrorCode::Forbidden, format!("{} 통로는 지금 사용할 수 없습니다", route.label(&self.topo))));
        }
        if !self.user_networks(c.user_id)?.contains(to) {
            return Err(ApiError::new(ErrorCode::Forbidden, format!("{}을(를) 사용할 권한이 없습니다", self.topo.name(to))));
        }
        Ok(p)
    }

    /// Enabled routes the user can send on from `side`.
    pub fn routes_for(&self, user_id: i64, side: &NetId) -> Result<Vec<RoutePolicy>, ApiError> {
        let nets = self.user_networks(user_id)?;
        let g = self.db.policy()?;
        Ok(self.route_policies()?.into_iter().filter(|p| p.enabled && p.route.from == *side && nets.contains(&p.route.to)).map(|p| p.resolved(&g)).collect())
    }
}
