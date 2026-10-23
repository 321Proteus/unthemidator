#ifndef UNTHEMIDATOR_WINDOWS_STRUCTS_HPP
#define UNTHEMIDATOR_WINDOWS_STRUCTS_HPP

#include <cstddef>
#include <cstdint>

namespace unthemidator::windows {
    constexpr uint32_t k_process_id = 0x1000;
    constexpr uint32_t k_thread_id = 0x1004;

    static_assert(sizeof(void *) == 8, "Windows structures in this header require a 64-bit target");

#pragma pack(push, 1)

    struct s_idtr {
        std::uint16_t limit;
        std::uintptr_t base;
    };

    struct s_idtr32 {
        std::uint16_t limit;
        std::uint32_t base;
    };

    static_assert(sizeof(s_idtr32) == 6);
    using s_gdtr = s_idtr;

    static_assert(sizeof(s_idtr) == 10);
    static_assert(sizeof(s_gdtr) == 10);

    union s_segment_selector {
        std::uint16_t all;

        struct {
            std::uint16_t rpl: 2; //!< Requested Privilege Level
            std::uint16_t ti: 1; //!< Table Indicator
            std::uint16_t index: 13;
        } fields;
    };

    static_assert(sizeof(s_segment_selector) == 2);

    union s_segment_descriptor {
        std::uint64_t all;

        struct {
            std::uint64_t limit_low: 16;
            std::uint64_t base_low: 16;
            std::uint64_t base_mid: 8;
            std::uint64_t type: 4;
            std::uint64_t system: 1;
            std::uint64_t dpl: 2;
            std::uint64_t present: 1;
            std::uint64_t limit_high: 4;
            std::uint64_t avl: 1;
            std::uint64_t l: 1; //!< 64-bit code segment (IA-32e mode only)
            std::uint64_t db: 1;
            std::uint64_t gran: 1;
            std::uint64_t base_high: 8;
        } fields;
    };

    static_assert(sizeof(s_segment_descriptor) == 8);

    struct s_segment_descriptor_x64 {
        s_segment_descriptor descriptor;
        std::uint32_t base_upper32;
        std::uint32_t reserved;
    };

    static_assert(sizeof(s_segment_descriptor_x64) == 16);

#pragma pack(pop)

    enum class e_msr : unsigned int {
        k_ia32_apic_base = 0x01B,

        k_ia32_feature_control = 0x03A,

        k_ia32_sysenter_cs = 0x174,
        k_ia32_sysenter_esp = 0x175,
        k_ia32_sysenter_eip = 0x176,

        k_ia32_debugctl = 0x1D9,

        k_ia32_mtrr_cap = 0xFE,
        k_ia32_mtrr_def_type = 0x2FF,
        k_ia32_mtrr_phys_base_n = 0x200,
        k_ia32_mtrr_phys_mask_n = 0x201,
        k_ia32_mtrr_fix64k00000 = 0x250,
        k_ia32_mtrr_fix16k80000 = 0x258,
        k_ia32_mtrr_fix16k_a0000 = 0x259,
        k_ia32_mtrr_fix4k_c0000 = 0x268,
        k_ia32_mtrr_fix4k_c8000 = 0x269,
        k_ia32_mtrr_fix4k_d0000 = 0x26A,
        k_ia32_mtrr_fix4k_d8000 = 0x26B,
        k_ia32_mtrr_fix4k_e0000 = 0x26C,
        k_ia32_mtrr_fix4k_e8000 = 0x26D,
        k_ia32_mtrr_fix4k_f0000 = 0x26E,
        k_ia32_mtrr_fix4k_f8000 = 0x26F,

        k_ia32_vmx_basic = 0x480,
        k_ia32_vmx_pinbased_ctls = 0x481,
        k_ia32_vmx_proc_based_ctls = 0x482,
        k_ia32_vmx_exit_ctls = 0x483,
        k_ia32_vmx_entry_ctls = 0x484,
        k_ia32_vmx_misc = 0x485,
        k_ia32_vmx_cr0_fixed0 = 0x486,
        k_ia32_vmx_cr0_fixed1 = 0x487,
        k_ia32_vmx_cr4_fixed0 = 0x488,
        k_ia32_vmx_cr4_fixed1 = 0x489,
        k_ia32_vmx_vmcs_enum = 0x48A,
        k_ia32_vmx_proc_based_ctls2 = 0x48B,
        k_ia32_vmx_ept_vpid_cap = 0x48C,
        k_ia32_vmx_true_pinbased_ctls = 0x48D,
        k_ia32_vmx_true_proc_based_ctls = 0x48E,
        k_ia32_vmx_true_exit_ctls = 0x48F,
        k_ia32_vmx_true_entry_ctls = 0x490,
        k_ia32_vmx_vmfunc = 0x491,

        k_ia32_efer = 0xC0000080,
        k_ia32_star = 0xC0000081,
        k_ia32_lstar = 0xC0000082,

        k_ia32_fmask = 0xC0000084,

        k_ia32_fs_base = 0xC0000100,
        k_ia32_gs_base = 0xC0000101,
        k_ia32_kernel_gs_base = 0xC0000102,
        k_ia32_tsc_aux = 0xC0000103,
    };

    union s_flag_register {
        std::uintptr_t all;

        struct {
            std::uintptr_t cf: 1; //!< [0] Carry flag
            std::uintptr_t reserved1: 1; //!< [1] Always 1
            std::uintptr_t pf: 1; //!< [2] Parity flag
            std::uintptr_t reserved2: 1; //!< [3] Always 0
            std::uintptr_t af: 1; //!< [4] Borrow flag
            std::uintptr_t reserved3: 1; //!< [5] Always 0
            std::uintptr_t zf: 1; //!< [6] Zero flag
            std::uintptr_t sf: 1; //!< [7] Sign flag
            std::uintptr_t tf: 1; //!< [8] Trap flag
            std::uintptr_t intf: 1; //!< [9] Interrupt flag
            std::uintptr_t df: 1; //!< [10] Direction flag
            std::uintptr_t of: 1; //!< [11] Overflow flag
            std::uintptr_t iopl: 2; //!< [12:13] I/O privilege level
            std::uintptr_t nt: 1; //!< [14] Nested task flag
            std::uintptr_t reserved4: 1; //!< [15] Always 0
            std::uintptr_t rf: 1; //!< [16] Resume flag
            std::uintptr_t vm: 1; //!< [17] Virtual 8086 mode
            std::uintptr_t ac: 1; //!< [18] Alignment check
            std::uintptr_t vif: 1; //!< [19] Virtual interrupt flag
            std::uintptr_t vip: 1; //!< [20] Virtual interrupt pending
            std::uintptr_t id: 1; //!< [21] Identification flag
            std::uintptr_t reserved5: 10; //!< [22:31] Reserved
        } fields;
    };

    static_assert(sizeof(s_flag_register) == sizeof(void *));

    constexpr std::uint32_t k_irp_mj_create = 0x00;
    constexpr std::uint32_t k_irp_mj_create_named_pipe = 0x01;
    constexpr std::uint32_t k_irp_mj_close = 0x02;
    constexpr std::uint32_t k_irp_mj_read = 0x03;
    constexpr std::uint32_t k_irp_mj_write = 0x04;
    constexpr std::uint32_t k_irp_mj_query_information = 0x05;
    constexpr std::uint32_t k_irp_mj_set_information = 0x06;
    constexpr std::uint32_t k_irp_mj_query_ea = 0x07;
    constexpr std::uint32_t k_irp_mj_set_ea = 0x08;
    constexpr std::uint32_t k_irp_mj_flush_buffers = 0x09;
    constexpr std::uint32_t k_irp_mj_query_volume_information = 0x0a;
    constexpr std::uint32_t k_irp_mj_set_volume_information = 0x0b;
    constexpr std::uint32_t k_irp_mj_directory_control = 0x0c;
    constexpr std::uint32_t k_irp_mj_file_system_control = 0x0d;
    constexpr std::uint32_t k_irp_mj_device_control = 0x0e;
    constexpr std::uint32_t k_irp_mj_internal_device_control = 0x0f;
    constexpr std::uint32_t k_irp_mj_shutdown = 0x10;
    constexpr std::uint32_t k_irp_mj_lock_control = 0x11;
    constexpr std::uint32_t k_irp_mj_cleanup = 0x12;
    constexpr std::uint32_t k_irp_mj_create_mailslot = 0x13;
    constexpr std::uint32_t k_irp_mj_query_security = 0x14;
    constexpr std::uint32_t k_irp_mj_set_security = 0x15;
    constexpr std::uint32_t k_irp_mj_power = 0x16;
    constexpr std::uint32_t k_irp_mj_system_control = 0x17;
    constexpr std::uint32_t k_irp_mj_device_change = 0x18;
    constexpr std::uint32_t k_irp_mj_query_quota = 0x19;
    constexpr std::uint32_t k_irp_mj_set_quota = 0x1a;
    constexpr std::uint32_t k_irp_mj_pnp = 0x1b;
    constexpr std::uint32_t k_irp_mj_pnp_power = k_irp_mj_pnp;
    constexpr std::uint32_t k_irp_mj_maximum_function = 0x1b;

    template<class T>
    struct s_list_entry {
        T flink;
        T blink;
    };

    struct s_unicode_string {
        std::uint16_t length;
        std::uint16_t maximum_length;
        char16_t *buffer;
    };

    static_assert(sizeof(s_unicode_string) == 16);

    struct s_system_basic_information {
        std::uint32_t reserved;
        std::uint32_t timer_resolution;
        std::uint32_t page_size;
        std::uint32_t number_of_physical_pages;
        std::uint32_t lowest_physical_page_number;
        std::uint32_t highest_physical_page_number;
        std::uint32_t allocation_granularity;
        std::uintptr_t minimum_user_mode_address;
        std::uintptr_t maximum_user_mode_address;
        std::uintptr_t active_processors_affinity_mask;
        char number_of_processors;
    };

    struct s_driver_object {
        std::int16_t type;
        std::int16_t size;
        void *device_object;
        std::uint32_t flags;
        void *driver_start;
        std::uint32_t driver_size;
        void *driver_section;
        void *driver_extension;
        s_unicode_string driver_name;
        s_unicode_string *hardware_database;
        void *fast_io_dispatch;
        void *driver_init;
        void *driver_start_io;
        void *driver_unload;
        void *major_function[k_irp_mj_maximum_function + 1];
    };

    enum class e_system_information_class_ex : std::uint32_t {
        k_system_basic_information = 0x0,
        k_system_processor_information = 0x1,
        k_system_path_information = 0x4,
        k_system_call_count_information = 0x6,
        k_system_device_information = 0x7,
        k_system_flags_information = 0x9,
        k_system_call_time_information = 0xa,
        k_system_module_information = 0xb,
        k_system_locks_information = 0xc,
        k_system_stack_trace_information = 0xd,
        k_system_paged_pool_information = 0xe,
        k_system_non_paged_pool_information = 0xf,
        k_system_handle_information = 0x10,
        k_system_object_information = 0x11,
        k_system_page_file_information = 0x12,
        k_system_vdm_instemul_information = 0x13,
        k_system_vdm_bop_information = 0x14,
        k_system_file_cache_information = 0x15,
        k_system_pool_tag_information = 0x16,
        k_system_dpc_behavior_information = 0x18,
        k_system_full_memory_information = 0x19,
        k_system_load_gdi_driver_information = 0x1a,
        k_system_unload_gdi_driver_information = 0x1b,
        k_system_time_adjustment_information = 0x1c,
        k_system_summary_memory_information = 0x1d,
        k_system_mirror_memory_information = 0x1e,
        k_system_performance_trace_information = 0x1f,
        k_system_obsolete0 = 0x20,
        k_system_crash_dump_state_information = 0x22,
        k_system_kernel_debugger_information = 0x23,
        k_system_context_switch_information = 0x24,
        k_system_extend_service_table_information = 0x26,
        k_system_priority_seperation = 0x27,
        k_system_verifier_add_driver_information = 0x28,
        k_system_verifier_remove_driver_information = 0x29,
        k_system_processor_idle_information = 0x2a,
        k_system_legacy_driver_information = 0x2b,
        k_system_current_time_zone_information = 0x2c,
        k_system_time_slip_notification = 0x2e,
        k_system_session_create = 0x2f,
        k_system_session_detach = 0x30,
        k_system_session_information = 0x31,
        k_system_range_start_information = 0x32,
        k_system_verifier_information = 0x33,
        k_system_verifier_thunk_extend = 0x34,
        k_system_session_process_information = 0x35,
        k_system_load_gdi_driver_in_system_space = 0x36,
        k_system_numa_processor_map = 0x37,
        k_system_prefetcher_information = 0x38,
        k_system_extended_process_information = 0x39,
        k_system_recommended_shared_data_alignment = 0x3a,
        k_system_com_plus_package = 0x3b,
        k_system_numa_available_memory = 0x3c,
        k_system_processor_power_information = 0x3d,
        k_system_emulation_basic_information = 0x3e,
        k_system_emulation_processor_information = 0x3f,
        k_system_extended_handle_information = 0x40,
        k_system_lost_delayed_write_information = 0x41,
        k_system_big_pool_information = 0x42,
        k_system_session_pool_tag_information = 0x43,
        k_system_session_mapped_view_information = 0x44,
        k_system_hotpatch_information = 0x45,
        k_system_object_security_mode = 0x46,
        k_system_watchdog_timer_handler = 0x47,
        k_system_watchdog_timer_information = 0x48,
        k_system_logical_processor_information = 0x49,
        k_system_wow64_shared_information_obsolete = 0x4a,
        k_system_register_firmware_table_information_handler = 0x4b,
        k_system_firmware_table_information = 0x4c,
        k_system_module_information_ex = 0x4d,
        k_system_verifier_triage_information = 0x4e,
        k_system_superfetch_information = 0x4f,
        k_system_memory_list_information = 0x50,
        k_system_file_cache_information_ex = 0x51,
        k_system_thread_priority_client_id_information = 0x52,
        k_system_processor_idle_cycle_time_information = 0x53,
        k_system_verifier_cancellation_information = 0x54,
        k_system_processor_power_information_ex = 0x55,
        k_system_ref_trace_information = 0x56,
        k_system_special_pool_information = 0x57,
        k_system_process_id_information = 0x58,
        k_system_error_port_information = 0x59,
        k_system_boot_environment_information = 0x5a,
        k_system_hypervisor_information = 0x5b,
        k_system_verifier_information_ex = 0x5c,
        k_system_time_zone_information = 0x5d,
        k_system_image_file_execution_options_information = 0x5e,
        k_system_coverage_information = 0x5f,
        k_system_prefetch_patch_information = 0x60,
        k_system_verifier_faults_information = 0x61,
        k_system_system_partition_information = 0x62,
        k_system_system_disk_information = 0x63,
        k_system_processor_performance_distribution = 0x64,
        k_system_numa_proximity_node_information = 0x65,
        k_system_dynamic_time_zone_information = 0x66,
        k_system_code_integrity_information_ = 0x67,
        k_system_processor_microcode_update_information = 0x68,
        k_system_processor_brand_string = 0x69,
        k_system_virtual_address_information = 0x6a,
        k_system_logical_processor_and_group_information = 0x6b,
        k_system_processor_cycle_time_information = 0x6c,
        k_system_store_information = 0x6d,
        k_system_registry_append_string = 0x6e,
        k_system_ait_sampling_value = 0x6f,
        k_system_vhd_boot_information = 0x70,
        k_system_cpu_quota_information = 0x71,
        k_system_native_basic_information = 0x72,
        k_system_error_port_timeouts = 0x73,
        k_system_low_priority_io_information = 0x74,
        k_system_boot_entropy_information = 0x75,
        k_system_verifier_counters_information = 0x76,
        k_system_paged_pool_information_ex = 0x77,
        k_system_system_ptes_information_ex = 0x78,
        k_system_node_distance_information = 0x79,
        k_system_acpi_audit_information = 0x7a,
        k_system_basic_performance_information = 0x7b,
        k_system_query_performance_counter_information = 0x7c,
        k_system_session_big_pool_information = 0x7d,
        k_system_boot_graphics_information = 0x7e,
        k_system_scrub_physical_memory_information = 0x7f,
        k_system_bad_page_information = 0x80,
        k_system_processor_profile_control_area = 0x81,
        k_system_combine_physical_memory_information = 0x82,
        k_system_entropy_interrupt_timing_information = 0x83,
        k_system_console_information = 0x84,
        k_system_platform_binary_information = 0x85,
        k_system_throttle_notification_information = 0x86,
        k_system_hypervisor_processor_count_information = 0x87,
        k_system_device_data_information = 0x88,
        k_system_device_data_enumeration_information = 0x89,
        k_system_memory_topology_information = 0x8a,
        k_system_memory_channel_information = 0x8b,
        k_system_boot_logo_information = 0x8c,
        k_system_processor_performance_information_ex = 0x8d,
        k_system_spare0 = 0x8e,
        k_system_secure_boot_policy_information = 0x8f,
        k_system_page_file_information_ex = 0x90,
        k_system_secure_boot_information = 0x91,
        k_system_entropy_interrupt_timing_raw_information = 0x92,
        k_system_portable_workspace_efi_launcher_information = 0x93,
        k_system_full_process_information = 0x94,
        k_system_kernel_debugger_information_ex = 0x95,
        k_system_boot_metadata_information = 0x96,
        k_system_soft_reboot_information = 0x97,
        k_system_elam_certificate_information = 0x98,
        k_system_offline_dump_config_information = 0x99,
        k_system_processor_features_information = 0x9a,
        k_system_registry_reconciliation_information = 0x9b,

        k_system_kernel_va_shadow_information = 196,
        k_max_system_info_class = 0x9c,
    };

    enum class e_process_info_class : std::uint32_t {
        k_process_basic_information,
        k_process_quota_limits,
        k_process_io_counters,
        k_process_vm_counters,
        k_process_times,
        k_process_base_priority,
        k_process_raise_priority,
        k_process_debug_port,
        k_process_exception_port,
        k_process_access_token,
        k_process_ldt_information,
        k_process_ldt_size,
        k_process_default_hard_error_mode,
        k_process_io_port_handlers,
        k_process_pooled_usage_and_limits,
        k_process_working_set_watch,
        k_process_user_mode_iopl,
        k_process_enable_alignment_fault_fixup,
        k_process_priority_class,
        k_process_wx86_information,
        k_process_handle_count,
        k_process_affinity_mask,
        k_process_priority_boost,
        k_max_process_info_class
    };

    struct s_process_basic_information {
        std::int32_t exit_status; // The exit status of the process. (GetExitCodeProcess)
        void *peb_base_address; // A pointer to the process environment block (PEB) of the process.
        std::uintptr_t affinity_mask; // The affinity mask of the process. (GetProcessAffinityMask) (deprecated)
        std::int32_t base_priority; // The base priority of the process. (GetPriorityClass)
        void *unique_process_id; // The unique identifier of the process. (GetProcessId)
        void *inherited_from_unique_process_id; // The unique identifier of the parent process.
    };

    enum class e_thread_info_class : std::uint32_t {
        k_thread_basic_information,
        k_thread_times,
        k_thread_priority,
        k_thread_base_priority,
        k_thread_affinity_mask,
        k_thread_impersonation_token,
        k_thread_descriptor_table_entry,
        k_thread_enable_alignment_fault_fixup,
        k_thread_event_pair,
        k_thread_query_set_win32_start_address,
        k_thread_zero_tls_cell,
        k_thread_performance_count,
        k_thread_am_ilast_thread,
        k_thread_ideal_processor,
        k_thread_priority_boost,
        k_thread_set_tls_array_address,
        k_thread_is_io_pending,
        k_thread_hide_from_debugger
    };

    struct s_client_id {
        void *unique_process;
        void *unique_thread;
    };

    static_assert(sizeof(s_client_id) == 16);

    struct s_thread_basic_information {
        std::int32_t exit_status;
        void *teb_base_address;
        s_client_id client_id;
        std::uintptr_t affinity_mask;
        std::int32_t priority;
        std::int32_t base_priority;
    };

    template<class T>
    struct s_ldr_data_table_entry {
        s_list_entry<T> in_load_order_module_list;
        s_list_entry<T> in_memory_order_module_list;
        s_list_entry<T> in_initialization_order_module_list;
        T dll_base;
        T entry_point;
        std::uint32_t size_of_image;
        s_unicode_string full_dll_name;
        s_unicode_string base_dll_name;
        std::uint32_t flags;
        std::uint16_t load_count;
        std::uint16_t tls_index;

        union {
            s_list_entry<T> hash_links;

            struct {
                T section_pointer;
                std::uint32_t check_sum;
            };
        };

        union {
            std::uint32_t time_date_stamp;
            T loaded_imports;
        };

        T entry_point_activation_context;
        T patch_information;
    };

    struct s_rtl_process_module_information {
        void *section; // Not filled in
        void *mapped_base;
        void *image_base;
        std::uint32_t image_size;
        std::uint32_t flags;
        std::uint16_t load_order_index;
        std::uint16_t init_order_index;
        std::uint16_t load_count;
        std::uint16_t offset_to_file_name;
        std::uint8_t full_path_name[256];
    };

    struct s_rtl_user_process_parameters_ex {
        std::uint32_t maximum_length; //+0
        std::uint32_t length; //+4
        std::uint32_t flags; //+8
        std::uint32_t debug_flags; //+12
        void *console_handle; //+16
        std::uint32_t console_flags; //+24
        void *std_input_handle; //+32
        void *std_output_handle; //+40
        void *std_error_handle; //+48
        s_unicode_string current_directory_path; //+56
        void *current_directory_handle; //+72
        s_unicode_string dll_path; //+80
        s_unicode_string image_path_name; //Offset=96 in x64
        s_unicode_string command_line;
    };

    struct s_rtl_process_modules {
        std::uint32_t number_of_modules;
        s_rtl_process_module_information modules[1];
    };

    struct s_rtl_critical_section_64 {
        std::uint64_t debug_info;
        std::uint32_t lock_count;
        std::uint32_t recursion_count;
        std::uint64_t owning_thread;
        std::uint64_t lock_semaphore;
        std::uint64_t spin_count;
    };

    struct s_mdl {
        struct s_mdl *next;
        std::int16_t size;
        std::int16_t mdl_flags;

        void *process;
        void *mapped_system_va; /* see creators for field size annotations. */
        void *start_va; /* see creators for validity; could be address 0.  */
        std::uint32_t byte_count;
        std::uint32_t byte_offset;
    };

    struct s_system_kernel_debugger_information {
        std::uint8_t debugger_enabled;
        std::uint8_t debugger_not_present;
    };

    struct s_kldr_data_table_entry {
        s_list_entry<std::uint64_t> in_load_order_links;
        void *exception_table;
        std::uint32_t exception_table_size;
        void *gp_value;
        void *non_paged_debug_info;
        void *dll_base;
        void *entry_point;
        std::uint32_t size_of_image;
        s_unicode_string full_dll_name;
        s_unicode_string base_dll_name;
        std::uint32_t flags;
        std::uint16_t load_count;
        std::uint16_t __Unused5;
        void *section_pointer;
        std::uint32_t check_sum;
        void *loaded_imports;
        void *patch_information;
    };

    constexpr std::uint32_t k_unwind_history_table_none = 0;
    constexpr std::uint32_t k_unwind_history_table_global = 1;
    constexpr std::uint32_t k_unwind_history_table_local = 2;

    constexpr std::uint32_t k_maximum_inverted_function_table_size = 160;

    struct s_inverted_function_table_entry {
        void *function_table;
        void *image_base;
        std::uint32_t size_of_image;
        std::uint32_t size_of_table;
    };

    struct s_inverted_function_table {
        std::uint32_t current_size;
        std::uint32_t maximum_size;
        std::uint8_t overflow;
        s_inverted_function_table_entry table_entry[k_maximum_inverted_function_table_size];
    };

    enum class e_unwind_op_codes : std::uint32_t {
        k_uwop_push_nonvol = 0,
        k_uwop_alloc_large,
        k_uwop_alloc_small,
        k_uwop_set_fpreg,
        k_uwop_save_nonvol,
        k_uwop_save_nonvol_far,
        k_uwop_spare_code1,
        k_uwop_spare_code2,
        k_uwop_save_xmm128,
        k_uwop_save_xmm128_far,
        k_uwop_push_machframe
    };

    union s_unwind_code {
        struct {
            std::uint8_t code_offset;
            std::uint8_t unwind_op: 4;
            std::uint8_t op_info: 4;
        };

        std::uint16_t frame_offset;
    };

    constexpr std::uint32_t k_unw_flag_nhandler = 0x0;
    constexpr std::uint32_t k_unw_flag_ehandler = 0x1;
    constexpr std::uint32_t k_unw_flag_uhandler = 0x2;
    constexpr std::uint32_t k_unw_flag_chaininfo = 0x4;

    struct s_unwind_info {
        std::uint8_t version: 3;
        std::uint8_t flags: 5;
        std::uint8_t size_of_prolog;
        std::uint8_t count_of_codes;
        std::uint8_t frame_register: 4;
        std::uint8_t frame_offset: 4;
        s_unwind_code unwind_code[1];
    };

    template<class T>
    struct s_peb_ldr_data {
        std::uint32_t length;
        std::uint8_t initialized;
        T ss_handle;
        s_list_entry<T> in_load_order_module_list;
        s_list_entry<T> in_memory_order_module_list;
        s_list_entry<T> in_initialization_order_module_list;
    };

    struct s_rtl_user_process_parameters {
        std::uint8_t reserved1[16];
        void *reserved2[10];
        s_unicode_string image_path_name;
        s_unicode_string command_line;
    };

    struct s_peb {
        std::uint8_t inherited_address_space;
        std::uint8_t read_image_file_exec_options;
        std::uint8_t being_debugged;
        std::uint8_t bit_field;
        std::uint32_t image_uses_large_pages: 1;
        std::uint32_t is_protected_process: 1;
        std::uint32_t is_legacy_process: 1;
        std::uint32_t is_image_dynamically_relocated: 1;
        std::uint32_t spare_bits: 4;
        void *mutant;
        void *image_base_address;
        s_peb_ldr_data<std::uint64_t> *ldr;
        s_rtl_user_process_parameters *process_parameters;
        void *sub_system_data;
        void *process_heap;
        void *fast_peb_lock;
        void *atl_thunk_slist_ptr;
        void *ifeokey;
        std::uint32_t cross_process_flags;
        std::uint32_t process_in_job: 1;
        std::uint32_t process_initializing: 1;
        std::uint32_t reserved_bits0: 30;

        union {
            void *kernel_callback_table;
            void *user_shared_info_ptr;
        };

        std::uint32_t system_reserved[1];
        std::uint32_t spare_ulong;
        void *free_list;
        std::uint32_t tls_expansion_counter;
        void *tls_bitmap;
        std::uint32_t tls_bitmap_bits[2];
        void *read_only_shared_memory_base;
        void *hotpatch_information;
        void * *read_only_static_server_data;
        void *ansi_code_page_data;
        void *oem_code_page_data;
        void *unicode_case_table_data;
        std::uint32_t number_of_processors;
        std::uint32_t nt_global_flag;
        std::uint32_t critical_section_timeout;
        std::uint32_t heap_segment_reserve;
        std::uint32_t heap_segment_commit;
        std::uint32_t heap_de_commit_total_free_threshold;
        std::uint32_t heap_de_commit_free_block_threshold;
        std::uint32_t number_of_heaps;
        std::uint32_t maximum_number_of_heaps;
        void * *process_heaps;
        void *gdi_shared_handle_table;
        void *process_starter_helper;
        std::uint32_t gdi_dcattribute_list;
        void *loader_lock;
        std::uint32_t osmajor_version;
        std::uint32_t osminor_version;
        std::uint16_t osbuild_number;
        std::uint16_t oscsdversion;
        std::uint32_t osplatform_id;
        std::uint32_t image_subsystem;
        std::uint32_t image_subsystem_major_version;
        std::uint32_t image_subsystem_minor_version;
        std::uint32_t image_process_affinity_mask;
        std::uint32_t gdi_handle_buffer[34];
        void *post_process_init_routine;
        void *tls_expansion_bitmap;
        std::uint32_t tls_expansion_bitmap_bits[32];
        std::uint32_t session_id;
        std::uint32_t app_compat_flags;
        std::uint32_t app_compat_flags_user;
        void *p_shim_data;
        void *app_compat_info;
        s_unicode_string csdversion;
        void *activation_context_data;
        void *process_assembly_storage_map;
        void *system_default_activation_context_data;
        void *system_assembly_storage_map;
        std::uint32_t minimum_stack_commit;
        void *fls_callback;
        s_list_entry<std::uint64_t> fls_list_head;
        void *fls_bitmap;
        std::uint32_t fls_bitmap_bits[4];
        std::uint32_t fls_high_index;
        void *wer_registration_data;
        void *wer_ship_assert_ptr;

        std::uint8_t bebra[0x1000];
    };

    struct s_teb {
        void *reserved1[12];
        s_peb *process_environment_block;
        void *reserved2[399];
        std::uint8_t reserved3[1952];
        void *tls_slots[64];
        std::uint8_t reserved4[8];
        void *reserved5[26];
        void *reserved_for_ole;
        void *reserved6[4];
        void *tls_expansion_slots;
    };

    struct s_startup_info_w {
        std::uint32_t cb;
        char16_t *lp_reserved;
        char16_t *lp_desktop;
        char16_t *lp_title;
        std::uint32_t dw_x;
        std::uint32_t dw_y;
        std::uint32_t dw_xsize;
        std::uint32_t dw_ysize;
        std::uint32_t dw_xcount_chars;
        std::uint32_t dw_ycount_chars;
        std::uint32_t dw_fill_attribute;
        std::uint32_t dw_flags;
        std::uint16_t w_show_window;
        std::uint16_t cb_reserved2;
        void *lp_reserved2;
        void *h_std_input;
        void *h_std_output;
        void *h_std_error;
    };

    struct s_cp_info {
        std::uint32_t max_char_size;
        std::uint8_t default_char[12];
        std::uint8_t lead_byte[12];
    };

    struct s_sock_addr {
        std::uint16_t sa_family;
        char sa_data[14];
    };

    struct s_object_attributes {
        std::uint32_t length;
        std::uint64_t root_directory;
        s_unicode_string *object_name;
        std::uint32_t attributes;
        void *security_descriptor;
        void *security_quality_of_service;
    };

    struct s_io_status_block {
        union {
            std::int32_t status;
            void *pointer;
        };

        std::uintptr_t information;
    };

    static_assert(sizeof(s_io_status_block) == 16);

    struct s_ws_addrinfo {
        int ai_flags;
        int ai_family;
        int ai_socktype;
        int ai_protocol;
        std::size_t ai_addrlen;
        char *ai_canonname;
        struct s_sock_addr *ai_addr;
        s_ws_addrinfo *ai_next;
    };

    struct s_overlapped {
        std::uint64_t internal;
        std::uint64_t internal_high;
        std::uint64_t pointer;
        void *h_event;
    };

    struct s_overlapped_entry {
        std::uintptr_t lp_completion_key;
        std::uint64_t lp_overlapped;
        std::uintptr_t internal;
        std::uint32_t dw_number_of_bytes_transferred;
    };

    struct s_kpcr {
        std::uint64_t gdt_base; // +0x000  (union with NtTib.GsBase)
        std::uint64_t tss_base; // +0x008
        std::uint64_t user_rsp; // +0x010
        std::uint64_t self; // +0x018  → points to this s_kpcr
        std::uint64_t current_prcb; // +0x020  → &s_kpcr.Prcb (s_kpcr base + 0x180)
        std::uint64_t lock_array; // +0x028
        std::uint64_t used_self; // +0x030
        std::uint64_t idt_base; // +0x038
        std::uint64_t unused0[2]; // +0x040
        std::uint16_t major_version; // +0x050
        std::uint16_t minor_version; // +0x052
        std::uint32_t stall_scale_factor; // +0x054
        std::uint64_t unused1[3]; // +0x058
        std::uint32_t kernel_reserved[15]; // +0x070
        std::uint32_t second_level_cache_size; // +0x0AC
        std::uint32_t hal_reserved[16]; // +0x0B0
        std::uint32_t unused2; // +0x0F0
        std::uint64_t kd_version_block; // +0x0F8
        std::uint64_t unused3; // +0x100
        std::uint32_t pcr_align1[24]; // +0x108

        std::uint8_t _pad_to_prcb[0x14]; // +0x16c to +0x180

        // Prcb starts at +0x180
        std::uint8_t mx_csr_and_early[0x8]; // +0x180
        std::uint64_t current_thread; // +0x188  ← gs:[0x188]
        std::uint64_t next_thread; // +0x190
        std::uint64_t idle_thread; // +0x198
        std::uint8_t nesting_level; // +0x1A0
        std::uint8_t clock_owner; // +0x1A1
        std::uint16_t pending_tick_flags; // +0x1A2
        std::uint32_t number; // +0x1A4  ← processor number
        std::uint64_t rsp_base; // +0x1A8
        std::uint64_t prcb_lock; // +0x1B0
        std::uint64_t priority_state; // +0x1B8
        std::uint8_t cpu_type; // +0x1C0
        std::uint8_t cpu_id; // +0x1C1
        std::uint16_t cpu_step; // +0x1C2
        std::uint32_t mhz; // +0x1C4
        std::uint64_t hal_reserved2[8]; // +0x1C8
        std::uint8_t _tail[0x7000 - 0x208];
    };

    static_assert(offsetof(s_kpcr, self) == 0x018, "s_kpcr.Self offset");
    static_assert(offsetof(s_kpcr, current_thread) == 0x188, "s_kpcr.Prcb.CurrentThread offset");
    static_assert(offsetof(s_kpcr, number) == 0x1A4, "s_kpcr.Prcb.Number offset");
    static_assert(sizeof(s_kpcr) == 0x7000, "s_kpcr size");

    struct s_kthread {
        // DISPATCHER_HEADER at +0x000
        std::uint8_t type; // +0x000
        std::uint8_t thread_control_flags; // +0x001
        std::uint8_t debug_active; // +0x002
        std::uint8_t dispatcher_header_reserved; // +0x003
        std::uint32_t signal_state; // +0x004
        std::uint64_t wait_list_head[2]; // +0x008  LIST_ENTRY

        std::uint64_t slist_fault_address; // +0x018
        std::uint64_t quantum_target; // +0x020
        std::uint64_t initial_stack; // +0x028
        std::uint64_t stack_limit; // +0x030
        std::uint64_t stack_base; // +0x038
        std::uint64_t thread_lock; // +0x040
        std::uint64_t cycle_time; // +0x048
        std::uint32_t current_run_time; // +0x050
        std::uint32_t expected_run_time; // +0x054
        std::uint64_t kernel_stack; // +0x058

        std::uint8_t _pad_060[0x220 - 0x060];

        std::uint64_t process; // +0x220  ← EPROCESS (as KPROCESS*)
        std::uint8_t _pad_228[0x2E0 - 0x228];

        std::uint64_t stack_base2; // +0x2E0
        std::uint8_t _pad_2E8[0x448 - 0x2E8];

        // CLIENT_ID at +0x448
        std::uint64_t unique_process; // +0x448  ← process id (as void*)
        std::uint64_t unique_thread; // +0x450  ← thread id (as void*)

        std::uint8_t _pad_458[0x5D0 - 0x458];

        std::uint64_t teb; // +0x5D0  ← usermode TEB pointer

        std::uint8_t _tail[0x8000 - 0x5D8];
    };

    static_assert(offsetof(s_kthread, process) == 0x220, "s_kthread.Process offset");
    static_assert(offsetof(s_kthread, unique_process) == 0x448, "s_kthread.Cid.UniqueProcess offset");
    static_assert(offsetof(s_kthread, unique_thread) == 0x450, "s_kthread.Cid.UniqueThread offset");
    static_assert(offsetof(s_kthread, teb) == 0x5D0, "s_kthread.Teb offset");
    static_assert(sizeof(s_kthread) == 0x8000, "s_kthread size");

    struct s_exception_pointers {
        uint64_t exception_record;
        uint64_t context_record;
    };

    struct s_exception_record {
        uint32_t exception_code;
        uint32_t exception_flags;
        uint64_t exception_record;
        uint64_t exception_address;
        uint32_t number_parameters;
        uint32_t reserved;
        uint64_t exception_information[15];
    };

    static_assert(sizeof(s_exception_pointers) == 16);
    static_assert(sizeof(s_exception_record) == 0x98);

#define align_size(Size, Align) ((Size+Align-1)/Align*Align)
} // namespace unthemidator::windows

#endif // UNTHEMIDATOR_WINDOWS_STRUCTS_HPP
