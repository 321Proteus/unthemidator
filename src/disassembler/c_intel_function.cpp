#include "c_intel_function.hpp"

#include <queue>
#include <ranges>

c_intel_basic_block *c_intel_function::find_common_predecessor(const std::vector<const c_intel_basic_block *> &blocks) {
    if (blocks.empty()) {
        return nullptr;
    }

    std::unordered_map<size_t, c_intel_basic_block *> by_id;

    for (auto &bb: m_basic_blocks) {
        by_id[bb.m_block_id] = &bb;
    }

    std::unordered_set<size_t> exit_ids{};

    for (auto *b: blocks) {
        exit_ids.insert(b->m_block_id);
    }

    auto is_reachable_backward = [&](const c_intel_basic_block *start) {
        std::unordered_map<size_t, int> dist{{start->m_block_id, 0}};

        std::queue<const c_intel_basic_block *> bb_queue{};
        bb_queue.push(start);

        while (!bb_queue.empty()) {
            const auto cur = bb_queue.front();
            bb_queue.pop();

            const int d = dist[cur->m_block_id];

            for (const auto pred_id : cur->m_predecessors) {
                if (!dist.emplace(pred_id, d + 1).second) {
                    continue;
                }

                if (auto it = by_id.find(pred_id); it != by_id.end()) {
                    bb_queue.push(it->second);
                }
            }
        }

        return dist;
    };

    std::vector<std::unordered_map<size_t, int> > reach{};
    reach.reserve(blocks.size());

    for (const auto bb: blocks) {
        reach.push_back(is_reachable_backward(bb));
    }

    size_t seed = 0;
    for (size_t i = 1; i < reach.size(); ++i) {
        if (reach[i].size() < reach[seed].size()) {
            seed = i;
        }
    }

    c_intel_basic_block *best = nullptr;
    int best_cost = INT_MAX;

    for (const auto &id: reach[seed] | std::views::keys) {
        if (exit_ids.contains(id)) {
            continue;
        }

        int cost = 0;
        bool common = true;

        for (auto &r: reach) {
            auto it = r.find(id);

            if (it == r.end()) {
                common = false;
                break;
            }

            cost = std::max(cost, it->second);
        }

        if (common && cost < best_cost) {
            best_cost = cost;
            best = by_id[id];
        }
    }

    return best;
}
