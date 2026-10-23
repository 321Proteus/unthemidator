#include <filesystem>

#include "c_emulator_ctx.hpp"
#include "../helpers/utils.hpp"
#include "../helpers/json.hpp"
#include "../pe/c_pe_image.hpp"
#include "../pe/pe_structs.hpp"
#include "../pe/pe_utils.hpp"

c_imports::c_imports(c_emulator_ctx *emulator_ctx) : m_emulator_ctx(emulator_ctx) {
    // create modules directory if it doesn't exist
    if (!std::filesystem::is_directory("modules")) {
        std::filesystem::create_directory("modules");
    }
}

uint64_t c_imports::load_module(std::string module_name) {
    std::ranges::transform(module_name, module_name.begin(), [](const unsigned char c) {
        return std::tolower(c);
    });

    if (m_module_addresses.contains(module_name)) {
        return m_module_addresses.at(module_name);
    }

    std::shared_ptr<c_pe_image> pe_image = nullptr;
    std::vector<s_dummy_export> exports = {};

    // if the module exists in local directory, load it from there
    if (std::filesystem::exists("modules/" + module_name)) {
        pe_image = std::make_shared<c_pe_image>(utils::read_file("modules/" + module_name));
    }

    const std::string catalog_name = m_emulator_ctx->get_arch() == e_architecture::k_x86 ?
        "catalog_32.json" : "catalog.json";

    // fallback to resolving from catalog
    if (!pe_image && std::filesystem::exists(catalog_name)) {
        std::ifstream catalog_stream(catalog_name);
        const auto catalog = nlohmann::json::parse(catalog_stream);
        catalog_stream.close();

        // resolve api set (if applicable)
        if (catalog.contains("api_sets") && catalog.at("api_sets").contains(module_name)) {
            module_name = catalog.at("api_sets").at(module_name).get<std::string>();
        }

        // manually parse exports if the record in catalog DOES exist
        if (catalog.contains("modules") && catalog.at("modules").contains(module_name)) {
            for (const auto &pe_export : catalog.at("modules").at(module_name).at(
                "exports").get<nlohmann::json::array_t>()) {
                //
                exports.push_back(s_dummy_export{
                    .m_name = pe_export.at("name").is_string() ? pe_export.at("name").get<std::string>() :
                        std::to_string(pe_export.at("ordinal").get<uint32_t>()),
                    .m_module = module_name,
                    .m_ordinal = pe_export.at("ordinal").get<uint32_t>(),
                    .m_entry_address = 0,
                });
            }
        }
    }

    if (!pe_image && exports.empty()) {
        return 0;
    }

    uint64_t original_image_base = 0x1000000;

    if (pe_image) {
        for (const auto &pe_export : pe_image->get_exports()) {
            exports.push_back(s_dummy_export{
                .m_name = pe_export.m_name,
                .m_module = module_name,
                .m_ordinal = pe_export.m_ordinal,
                .m_entry_address = 0,
            });
        }

        original_image_base = pe_image->get_image_base();
    }

    // create dummy DLL with export descriptors only
    const auto dummy = pe_utils::create_dummy_dll(m_emulator_ctx->get_arch(),
        original_image_base, module_name, exports);

    const auto image_base = m_emulator_ctx->map_dummy_module(dummy, module_name);

    const auto nt_offset = *reinterpret_cast<const uint32_t*>(dummy.data() +
        offsetof(unthemidator::pe::s_dos_header, e_lfanew));
    const auto optional_header = image_base + nt_offset + sizeof(uint32_t) +
        sizeof(unthemidator::pe::s_coff_header);

    // update base address
    switch (m_emulator_ctx->get_arch()) {
        case e_architecture::k_x86: {
            const auto new_base = static_cast<uint32_t>(image_base);

            uc_mem_write(m_emulator_ctx->get_uc(), optional_header +
                offsetof(unthemidator::pe::s_optional_header_32, image_base), &new_base, sizeof(new_base));

            break;
        }

        case e_architecture::k_amd64: {
            uc_mem_write(m_emulator_ctx->get_uc(), optional_header +
                offsetof(unthemidator::pe::s_optional_header_64, image_base), &image_base, sizeof(image_base));

            break;
        }

        default:
            throw std::runtime_error("unsupported architecture");
    }

    m_module_addresses.emplace(module_name, image_base);
    m_modules.emplace(image_base, module_name);
    m_exports_by_name.emplace(module_name, std::unordered_map<std::string, s_dummy_export>{});

    // save all export addresses
    for (auto &pe_export : exports) {
        pe_export.m_entry_address += image_base;

        m_exports_by_name.at(module_name).emplace(pe_export.m_name, pe_export);
        m_exports_by_va.emplace(pe_export.m_entry_address, std::make_pair(module_name, pe_export.m_name));

        //printf("0x%llX - %s %s\n", pe_export.m_entry_address, module_name.c_str(), pe_export.m_name.c_str());
    }

    return image_base;
}

uint64_t c_imports::resolve_import(const uint64_t module_base, const std::string &function_name) const {
    if (!m_modules.contains(module_base)) {
        return 0;
    }

    const auto &mod_exports = m_exports_by_name.at(m_modules.at(module_base));
    const auto it_export = mod_exports.find(function_name);

    if (it_export == mod_exports.end()) {
        return 0;
    }

    return it_export->second.m_entry_address;
}

const s_dummy_export * c_imports::find_import_by_address(const uint64_t address) {
    if (!m_exports_by_va.contains(address)) {
        return nullptr;
    }

    const auto &[mod_name, fn_name] = m_exports_by_va.at(address);
    return &m_exports_by_name.at(mod_name).at(fn_name);
}
