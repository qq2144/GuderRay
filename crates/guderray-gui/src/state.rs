//! In-memory cache of profiles/settings/subscriptions, loaded once at startup and
//! written through on mutation — replacing the old "reload from disk on every GUI
//! callback" pattern.
//!
//! `State` (the running-process record in `guderray_core::State`) deliberately does NOT
//! live here: the CLI and the GUI both read/write it to coordinate which process owns
//! the running sing-box core, so it must stay disk-authoritative on every access.

use guderray_core::{Paths, ProfileStore, Settings, SubStore};

pub struct AppState {
    pub paths: Paths,
    pub profiles: ProfileStore,
    pub settings: Settings,
    pub subs: SubStore,
}

impl AppState {
    pub fn load(paths: Paths) -> anyhow::Result<Self> {
        let profiles = ProfileStore::load(&paths)?;
        let settings = Settings::load(&paths)?;
        let subs = SubStore::load(&paths)?;
        Ok(AppState { paths, profiles, settings, subs })
    }

    pub fn save_profiles(&self) -> anyhow::Result<()> {
        self.profiles.save(&self.paths)?;
        Ok(())
    }

    pub fn save_settings(&self) -> anyhow::Result<()> {
        self.settings.save(&self.paths)?;
        Ok(())
    }

    pub fn save_subs(&self) -> anyhow::Result<()> {
        self.subs.save(&self.paths)?;
        Ok(())
    }

    /// Reload every store from disk in place. Use this ONLY after something outside
    /// this cache's control (a background thread calling an engine function that does
    /// its own disk I/O, e.g. `sub_add`/`sub_update`) has mutated disk state — otherwise
    /// a stale in-memory field could get written back and clobber that external change.
    pub fn reload(&mut self) -> anyhow::Result<()> {
        self.profiles = ProfileStore::load(&self.paths)?;
        self.settings = Settings::load(&self.paths)?;
        self.subs = SubStore::load(&self.paths)?;
        Ok(())
    }
}

// Arc<Mutex<..>>, not Rc<RefCell<..>>: several callbacks hand a closure that captures
// this state into `Weak::upgrade_in_event_loop`, which requires the closure (and
// everything it captures) to be `Send` — that closure is constructed on a background
// thread (after a subscription fetch, etc.) and queued onto the UI thread.
pub type SharedState = std::sync::Arc<std::sync::Mutex<AppState>>;

/// Lock the state, recovering from a poisoned mutex (a prior panic while holding the
/// lock) rather than letting one bad panic brick every future access to shared state.
pub fn lock(state: &SharedState) -> std::sync::MutexGuard<'_, AppState> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use guderray_core::model::{Outbound, Shadowsocks};
    use std::path::PathBuf;

    fn temp_paths(tag: &str) -> Paths {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "guderray-appstate-test-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = Paths { root: PathBuf::from(root) };
        paths.ensure().unwrap();
        paths
    }

    fn sample_outbound() -> Outbound {
        Outbound::Shadowsocks(Shadowsocks {
            server: "1.2.3.4".into(),
            port: 8388,
            method: "aes-256-gcm".into(),
            password: "p".into(),
        })
    }

    /// The core risk this phase introduces: does a mutate-in-memory + save actually
    /// reach disk, or does it just look right in the running process? Load a fresh
    /// AppState from a brand new directory, mutate it, save it, then load a SEPARATE
    /// AppState instance from the same directory and confirm it sees the mutation —
    /// this is the same "does a restart see it" check the plan's manual gate calls for,
    /// just automated instead of clicked through.
    #[test]
    fn profile_add_survives_a_fresh_load() {
        let paths = temp_paths("add");
        let id = {
            let mut st = AppState::load(paths.clone()).unwrap();
            let id = st.profiles.add("test-node".into(), None, sample_outbound());
            st.save_profiles().unwrap();
            id
        };
        let reloaded = AppState::load(paths.clone()).unwrap();
        let p = reloaded.profiles.get(id).unwrap();
        assert_eq!(p.name, "test-node");
        std::fs::remove_dir_all(&paths.root).ok();
    }

    #[test]
    fn profile_rename_survives_a_fresh_load() {
        let paths = temp_paths("rename");
        let id = {
            let mut st = AppState::load(paths.clone()).unwrap();
            let id = st.profiles.add("before".into(), None, sample_outbound());
            st.save_profiles().unwrap();
            id
        };
        {
            let mut st = AppState::load(paths.clone()).unwrap();
            st.profiles.rename(id, "after".into()).unwrap();
            st.save_profiles().unwrap();
        }
        let reloaded = AppState::load(paths.clone()).unwrap();
        assert_eq!(reloaded.profiles.get(id).unwrap().name, "after");
        std::fs::remove_dir_all(&paths.root).ok();
    }

    #[test]
    fn profile_delete_survives_a_fresh_load() {
        let paths = temp_paths("delete");
        let id = {
            let mut st = AppState::load(paths.clone()).unwrap();
            let id = st.profiles.add("gone".into(), None, sample_outbound());
            st.save_profiles().unwrap();
            id
        };
        {
            let mut st = AppState::load(paths.clone()).unwrap();
            st.profiles.remove(id).unwrap();
            st.save_profiles().unwrap();
        }
        let reloaded = AppState::load(paths.clone()).unwrap();
        assert!(reloaded.profiles.get(id).is_err());
        std::fs::remove_dir_all(&paths.root).ok();
    }

    #[test]
    fn settings_toggles_survive_a_fresh_load() {
        let paths = temp_paths("settings");
        {
            let mut st = AppState::load(paths.clone()).unwrap();
            st.settings.tun = true;
            st.settings.ui_dark_mode = false;
            st.settings.language = "en".into();
            st.settings.routing = guderray_core::RoutingMode::Global;
            st.save_settings().unwrap();
        }
        let reloaded = AppState::load(paths.clone()).unwrap();
        assert!(reloaded.settings.tun);
        assert!(!reloaded.settings.ui_dark_mode);
        assert_eq!(reloaded.settings.language, "en");
        assert_eq!(reloaded.settings.routing, guderray_core::RoutingMode::Global);
        std::fs::remove_dir_all(&paths.root).ok();
    }

    #[test]
    fn subscription_add_and_remove_survive_a_fresh_load() {
        let paths = temp_paths("subs");
        {
            let mut st = AppState::load(paths.clone()).unwrap();
            st.subs.upsert("feed".into(), "https://example.com/sub".into());
            st.save_subs().unwrap();
        }
        {
            let reloaded = AppState::load(paths.clone()).unwrap();
            assert!(reloaded.subs.get("feed").is_some());
        }
        {
            let mut st = AppState::load(paths.clone()).unwrap();
            st.subs.remove("feed");
            st.save_subs().unwrap();
        }
        let reloaded = AppState::load(paths.clone()).unwrap();
        assert!(reloaded.subs.get("feed").is_none());
        std::fs::remove_dir_all(&paths.root).ok();
    }

    /// Simulates the documented "background thread mutated disk, cache must reload"
    /// exception: one AppState instance saves a profile (standing in for an engine-layer
    /// function like sub_add/ping_profile writing to disk independently), while a SECOND
    /// AppState instance (standing in for the GUI's stale in-memory cache) has an older
    /// view. Calling `reload()` on the second instance must pick up the first's write —
    /// and, critically, must NOT then re-save and clobber it.
    #[test]
    fn reload_picks_up_a_concurrent_external_write_without_clobbering_it() {
        let paths = temp_paths("reload");
        let id = {
            let mut st = AppState::load(paths.clone()).unwrap();
            let id = st.profiles.add("original".into(), None, sample_outbound());
            st.save_profiles().unwrap();
            id
        };

        // GUI's cache, loaded before the "external" write below.
        let mut gui_cache = AppState::load(paths.clone()).unwrap();

        // An "external" writer (standing in for a background thread calling an
        // engine function) changes the profile's latency directly on disk.
        {
            let mut external = AppState::load(paths.clone()).unwrap();
            external.profiles.set_latency(id, Some(42), Some(1_700_000_000)).unwrap();
            external.save_profiles().unwrap();
        }

        // Before reload, the GUI's cache is stale (doesn't see the latency yet).
        assert_eq!(gui_cache.profiles.get(id).unwrap().latency, None);

        // reload() must pick up the external write...
        gui_cache.reload().unwrap();
        assert_eq!(gui_cache.profiles.get(id).unwrap().latency, Some(42));

        // ...and now if the GUI cache re-saves (e.g. an unrelated rename), the
        // externally-written latency must survive, not get clobbered by a stale copy.
        gui_cache.profiles.rename(id, "renamed".into()).unwrap();
        gui_cache.save_profiles().unwrap();
        let final_state = AppState::load(paths.clone()).unwrap();
        let p = final_state.profiles.get(id).unwrap();
        assert_eq!(p.name, "renamed");
        assert_eq!(p.latency, Some(42), "external write must not be clobbered by a stale save");

        std::fs::remove_dir_all(&paths.root).ok();
    }
}
