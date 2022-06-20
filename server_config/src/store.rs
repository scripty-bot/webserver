use once_cell::sync::OnceCell;

use crate::cfg::Config;

pub static GLOBAL_CONFIG: OnceCell<Config> = OnceCell::new();

pub fn get_cfg() -> &'static Config {
    GLOBAL_CONFIG
        .get()
        .expect("call `load_cfg()` before attempting to fetch it")
}
