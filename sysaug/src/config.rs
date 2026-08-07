use crate::common::{rwlock_write, SysAugError, SyscallInfo};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RenameConfig {
    #[serde(with = "serde_regex")]
    pub(crate) regex: Regex,

    /// If None, pcontainer will hide the file at this path.
    pub(crate) replacement: Option<String>,

    /// If false, replace only the earliest match.
    #[serde(default = "default_should_replace_all")]
    pub(crate) should_replace_all: bool,
}

fn default_should_replace_all() -> bool {
    false
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RootfsConfig {
    #[serde(default = "default_passthroughs")]
    pub(crate) passthroughs: Vec<String>,

    /// The key (original path) is a regex string with named captures. The value (new path) is a template string.
    #[serde(default = "default_rename_configs")]
    pub(crate) rename_guest_paths: Vec<RenameConfig>,

    #[serde(default = "default_rename_configs")]
    pub(crate) rename_host_paths: Vec<RenameConfig>,
}

fn default_passthroughs() -> Vec<String> {
    vec![
        // Linux systems
        "/dev".to_string(),
        "/proc".to_string(),
        "/sys".to_string(),
        // Android systems
        "/system/lib64".to_string(),
        "/system/lib".to_string(),
    ]
}

pub(crate) fn init_passthroughs_from_config(
    passthroughs: &mut Vec<PathBuf>,
    config: &RootfsConfig,
) {
    passthroughs.clear();
    for passthrough in &config.passthroughs {
        passthroughs.push(PathBuf::from(passthrough.clone()));
    }
}

fn default_rename_configs() -> Vec<RenameConfig> {
    vec![]
}

impl Default for RootfsConfig {
    fn default() -> Self {
        Self {
            passthroughs: default_passthroughs(),
            rename_guest_paths: default_rename_configs(),
            rename_host_paths: default_rename_configs(),
        }
    }
}

pub(crate) const PERMS_IDBIT_UG: u8 = 4;
pub(crate) const PERMS_IDS_SIZE: usize = 8;

/**
* Check the res_bits and resf_bit of a system call and call the callback for each slot that is set.
* @param callback: The three parameters are
     1. register index (0 to 2, or None for regs.syscall_retval)
     2. a mutable ref of the actual ID value to read/write (or None if no ID overrides exist)
* @param multi_getter_is_success: True if this is a setter syscall, or if the actual getresuid/getresgid/... syscall succeeded.
* @return true if the syscall fits a defined getid/setid pattern. (False for calls like setgroups, getgroups)
*/
#[inline(always)]
pub(crate) fn walk_resf_syscall(
    syscall: &SyscallInfo,
    multi_getter_is_success: bool,
    perms_ids: &RwLock<[Option<usize>; PERMS_IDS_SIZE]>,
    callback: impl Fn(Option<usize>, &mut Option<usize>) -> Result<(), SysAugError>,
) -> Result<bool, SysAugError> {
    let mut guard = rwlock_write(perms_ids)?;
    if let Some(resf_bit) = syscall.resf_bit {
        callback(None, &mut guard[resf_bit as usize])?;
        return Ok(true);
    } else if multi_getter_is_success {
        let ug_bit = syscall.res_bits & PERMS_IDBIT_UG;
        let res_bits = syscall.res_bits;
        for i in 0..2 {
            let mask = 1 << i;
            if res_bits & mask == 0 {
                continue;
            }

            let idx = ug_bit | (i as u8);
            callback(Some(i), &mut guard[idx as usize])?;
        }
        return Ok(true);
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[repr(u8)]
pub(crate) enum ResfUgType {
    RealUid = 0,
    EffectiveUid = 1,
    SavedSetUid = 2,
    FileSystemUid = 3,
    RealGid = PERMS_IDBIT_UG | 0,
    EffectiveGid = PERMS_IDBIT_UG | 1,
    SavedSetGid = PERMS_IDBIT_UG | 2,
    FileSystemGid = PERMS_IDBIT_UG | 3,
}

impl ResfUgType {
    pub fn index(self) -> usize {
        self as u8 as usize
    }
}

impl FromStr for ResfUgType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "realUid" => Ok(ResfUgType::RealUid),
            "effectiveUid" => Ok(ResfUgType::EffectiveUid),
            "savedSetUid" => Ok(ResfUgType::SavedSetUid),
            "fileSystemUid" => Ok(ResfUgType::FileSystemUid),
            "realGid" => Ok(ResfUgType::RealGid),
            "effectiveGid" => Ok(ResfUgType::EffectiveGid),
            "savedSetGid" => Ok(ResfUgType::SavedSetGid),
            "fileSystemGid" => Ok(ResfUgType::FileSystemGid),
            _ => Err(format!("Invalid ResfUgType: {}", s)),
        }
    }
}

pub(crate) fn init_perms_ids_from_config(
    perms_ids: &RwLock<[Option<usize>; PERMS_IDS_SIZE]>,
    config: &PermsConfig,
) -> Result<(), SysAugError> {
    let mut guard = rwlock_write(perms_ids)?;
    for (ty, id) in &config.root_ids {
        guard[ty.index()] = Some(*id);
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermsConfig {
    #[serde(default = "default_root_ids")]
    pub(crate) root_ids: HashMap<ResfUgType, usize>,
}

fn default_root_ids() -> HashMap<ResfUgType, usize> {
    let mut map = HashMap::new();
    map.insert(ResfUgType::RealUid, 0);
    map.insert(ResfUgType::EffectiveUid, 0);
    map.insert(ResfUgType::SavedSetUid, 0);
    map.insert(ResfUgType::FileSystemUid, 0);
    map.insert(ResfUgType::RealGid, 0);
    map.insert(ResfUgType::EffectiveGid, 0);
    map.insert(ResfUgType::SavedSetGid, 0);
    map.insert(ResfUgType::FileSystemGid, 0);
    map
}

impl Default for PermsConfig {
    fn default() -> Self {
        Self {
            root_ids: default_root_ids(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SysAugConfig {
    #[serde(default)]
    pub(crate) rootfs: RootfsConfig,
    #[serde(default)]
    pub(crate) perms: PermsConfig,
}

impl Default for SysAugConfig {
    fn default() -> Self {
        Self {
            rootfs: RootfsConfig::default(),
            perms: PermsConfig::default(),
        }
    }
}
