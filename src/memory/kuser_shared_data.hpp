#ifndef UNTHEMIDATOR_KUSER_SHARED_DATA_HPP
#define UNTHEMIDATOR_KUSER_SHARED_DATA_HPP

#include <cstddef>
#include <cstdint>

namespace unthemidator::windows {
    struct s_ksystem_time {
        uint32_t low_part;
        int32_t high1_time;
        int32_t high2_time;
    };

    struct s_xstate_configuration {
        uint64_t enabled_features, enabled_volatile_features;
        uint32_t size, control_flags;
        struct s_feature { uint32_t offset, size; } features[64];
        uint64_t enabled_supervisor_features, aligned_features;
        uint32_t all_feature_size, all_features[64];
        uint64_t enabled_user_visible_supervisor_features;
        uint64_t extended_feature_disable_features;
        uint32_t all_non_large_feature_size;
        uint16_t max_sve_vector_length, spare;
    };

    // Fixed-width Windows 11 x86/AMD64 shared-page layout. Flag unions are stored
    // as their raw integers; reserved/unused fields and the page tail stay zero.
    // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
    struct alignas(0x1000) s_kuser_shared_data {
        uint32_t tick_count_low_deprecated, tick_count_multiplier;
        s_ksystem_time interrupt_time, system_time, time_zone_bias;
        uint16_t image_number_low, image_number_high;
        char16_t nt_system_root[260];
        uint32_t max_stack_trace_depth, crypto_exponent, time_zone_id, large_page_minimum;
        uint32_t ait_sampling_value, app_compat_flag;
        uint64_t rng_seed_version;
        uint32_t global_validation_runlevel;
        int32_t time_zone_bias_stamp;
        uint32_t nt_build_number, nt_product_type;
        uint8_t product_type_is_valid, reserved0;
        uint16_t native_processor_architecture;
        uint32_t nt_major_version, nt_minor_version;
        uint8_t processor_features[64];
        uint32_t reserved1, reserved3, time_slip, alternative_architecture, boot_id;
        int64_t system_expiration_date;
        uint32_t suite_mask;
        uint8_t kd_debugger_enabled, mitigation_policies;
        uint16_t cycles_per_yield;
        uint32_t active_console_id, dismount_count, com_plus_package;
        uint32_t last_system_rit_event_tick_count, number_of_physical_pages;
        uint8_t safe_boot_mode, virtualization_flags, reserved12[2];
        uint32_t shared_data_flags, data_flags_pad;
        uint64_t test_ret_instruction;
        int64_t qpc_frequency;
        uint32_t system_call, reserved2;
        uint64_t full_number_of_physical_pages, system_call_pad;
        s_ksystem_time tick_count;
        uint32_t tick_count_pad, cookie, cookie_pad;
        int64_t console_session_foreground_process_id;
        uint64_t time_update_lock, baseline_system_time_qpc, baseline_interrupt_time_qpc;
        uint64_t qpc_system_time_increment, qpc_interrupt_time_increment;
        uint8_t qpc_system_time_increment_shift, qpc_interrupt_time_increment_shift;
        uint16_t unparked_processor_count;
        uint32_t enclave_feature_mask[4], telemetry_coverage_round;
        uint16_t user_mode_global_logger[16];
        uint32_t image_file_execution_options, lang_generation_count;
        uint64_t reserved4, interrupt_time_bias, qpc_bias;
        uint32_t active_processor_count;
        uint8_t active_group_count, reserved9, qpc_bypass_enabled, qpc_shift;
        int64_t time_zone_bias_effective_start, time_zone_bias_effective_end;
        s_xstate_configuration xstate;
        s_ksystem_time feature_configuration_change_stamp;
        uint32_t spare;
        uint64_t user_pointer_auth_mask;
        uint8_t reserved_tail[0x1000 - 0x738];
    };

    static_assert(sizeof(s_ksystem_time) == 12);
    static_assert(sizeof(s_xstate_configuration) == 0x348);
    static_assert(offsetof(s_kuser_shared_data, system_time) == 0x14);
    static_assert(offsetof(s_kuser_shared_data, nt_system_root) == 0x30);
    static_assert(offsetof(s_kuser_shared_data, nt_build_number) == 0x260);
    static_assert(offsetof(s_kuser_shared_data, processor_features) == 0x274);
    static_assert(offsetof(s_kuser_shared_data, kd_debugger_enabled) == 0x2D4);
    static_assert(offsetof(s_kuser_shared_data, qpc_frequency) == 0x300);
    static_assert(offsetof(s_kuser_shared_data, tick_count) == 0x320);
    static_assert(offsetof(s_kuser_shared_data, time_update_lock) == 0x340);
    static_assert(offsetof(s_kuser_shared_data, xstate) == 0x3D8);
    static_assert(offsetof(s_kuser_shared_data, feature_configuration_change_stamp) == 0x720);
    static_assert(offsetof(s_kuser_shared_data, reserved_tail) == 0x738);
    static_assert(sizeof(s_kuser_shared_data) == 0x1000);
}

#endif
