#[macro_export]
macro_rules! esp_app_desc {
    () => {
        #[no_mangle]
        #[used]
        #[link_section = ".rodata_desc"]
        #[allow(non_upper_case_globals)]
        pub static esp_app_desc: $crate::esp_app_desc_t = {
            const fn str_to_cstr_array<const C: usize>(s: &str) -> [$crate::c_types::c_char; C] {
                let mut ret: [$crate::c_types::c_char; C] = [0; C];

                let mut i = 0;
                while i < C {
                    if i < s.len() {
                        ret[i] = s.as_bytes()[i] as _;
                    } else {
                        break;
                    }

                    i += 1;
                }

                ret
            }

            $crate::esp_app_desc_t {
                magic_word: $crate::ESP_APP_DESC_MAGIC_WORD,
                secure_version: 0,
                reserv1: [0; 2],
                version: str_to_cstr_array(env!("CARGO_PKG_VERSION")),
                project_name: str_to_cstr_array(env!("CARGO_PKG_NAME")),
                time: str_to_cstr_array($crate::build_time::build_time_utc!("%Y-%m-%d")),
                date: str_to_cstr_array($crate::build_time::build_time_utc!("%H:%M:%S")),
                idf_ver: str_to_cstr_array($crate::const_format::formatcp!(
                    "{}.{}.{}",
                    $crate::ESP_IDF_VERSION_MAJOR,
                    $crate::ESP_IDF_VERSION_MINOR,
                    $crate::ESP_IDF_VERSION_PATCH
                )),
                app_elf_sha256: [0; 32],
                reserv2: [0; 20],
            }
        };
    };
}

/// Macro to allocate memory in firmware file for custom application descriptor
/// This data will be filled with 0xFF and expected to be filled with usefull data from
#[macro_export]
macro_rules! esp_custom_desc_placeholder {
    ($length: expr) => {
        #[no_mangle]
        #[used]
        #[link_section = ".rodata_custom_desc"]
        #[allow(non_upper_case_globals)]
        pub static esp_custom_desc_placeholder: [$crate::c_types::c_char; $length] =
            [0xFF; $length];
    };
}


///
/// #[derive(Copy, Clone)]
/// pub struct Sometype {
///     a: u32,
///     b: u32,
///     c: u8,
/// }
/// sys::esp_custom_desc!(1024, Sometype);
///
#[macro_export]
macro_rules! esp_custom_desc {
    ($length: expr, $internal_type: ty) => {
        #[repr(packed)]
        #[derive(Copy, Clone)]
        pub struct CustomAppDescriptorHeader {
            pub magic: u32,
            pub length: u32,
        }

        #[repr(packed)]
        #[derive(Copy, Clone)]
        pub struct CustomAppDescriptorData {
            pub header: CustomAppDescriptorHeader,
            pub internal: $internal_type,
        }

        #[repr(packed)]
        pub union CustomAppDescriptor {
            storage: [$crate::c_types::c_char; $length],
            data: CustomAppDescriptorData,
        }

        impl CustomAppDescriptor {

            pub fn load_data(&mut self) -> Result<(), $crate::EspError> {
                unsafe {
                    let partition = $crate::esp_ota_get_running_partition();

                    if !partition.is_null() {
                        let mut header: CustomAppDescriptorHeader = CustomAppDescriptorHeader {
                            magic: 0,
                            length: 0,
                        };
                        let err = $crate::esp_partition_read(
                            partition,
                            (std::mem::size_of::<$crate::esp_image_header_t>()
                                + std::mem::size_of::<$crate::esp_image_segment_header_t>()
                                + std::mem::size_of::<$crate::esp_app_desc_t>())
                                as u32,
                            (&mut header as *mut CustomAppDescriptorHeader)
                                as *mut $crate::c_types::c_void,
                            std::mem::size_of::<CustomAppDescriptorHeader>() as u32,
                        );

                        if err != $crate::ESP_OK {
                            return $crate::esp!(err);
                        }

                        if header.magic == 0x78563412 {
                            if (header.length <= std::mem::size_of::<CustomAppDescriptorHeader>() as u32) {
                                return $crate::esp!($crate::ESP_ERR_INVALID_SIZE);
                            }
                            let err = $crate::esp_partition_read(
                                partition,
                                (std::mem::size_of::<$crate::esp_image_header_t>()
                                    + std::mem::size_of::<$crate::esp_image_segment_header_t>()
                                    + std::mem::size_of::<$crate::esp_app_desc_t>())
                                    as u32,
                                (self as *mut CustomAppDescriptor) as *mut $crate::c_types::c_void,
                                std::mem::size_of::<CustomAppDescriptorHeader>() as u32,
                            );

                            if err != $crate::ESP_OK {
                                return $crate::esp!(err);
                            }
                        }
                    }

                    Ok(())
                }
            }
        }

        #[no_mangle]
        #[used]
        #[link_section = ".rodata_custom_desc"]
        #[allow(non_upper_case_globals)]
        pub static esp_custom_desc: CustomAppDescriptor = {
            assert!(
                $length >= std::mem::size_of::<$internal_type>(),
                "Allocated length is not enough for internal type"
            );
            CustomAppDescriptor {
                storage: [0xEE; $length],
            }
        };
    };
}
