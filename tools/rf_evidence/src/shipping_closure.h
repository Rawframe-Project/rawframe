#pragma once

#include "failure.h"
#include "repository_validator.h"

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

namespace rawframe::tool::evidence {

struct ShippingClosureCheck {
    std::string check;
    std::string subject;
    bool pass = false;
};

struct ShippingClosureAudit {
    std::vector<ShippingClosureCheck> checks;

    [[nodiscard]] bool allPassed() const noexcept {
        return std::ranges::all_of(checks, &ShippingClosureCheck::pass);
    }
};

// Mechanically proves that no repository tool can enter a shipping closure:
// production membership stays empty, every tool manifest forbids shipping,
// SDK, and target-root exposure, no production module or shipping root
// exists, and the tool build defines no install or export surface.
[[nodiscard]] Result<ShippingClosureAudit> auditShippingClosure(const std::filesystem::path& repositoryRoot,
                                                                const RepositorySnapshot& snapshot);

} // namespace rawframe::tool::evidence
