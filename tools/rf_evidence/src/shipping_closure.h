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
// production membership and tool membership stay on opposite sides of the
// repository-tool root, every tool manifest forbids shipping, SDK, and
// target-root exposure, every production module manifest lies beneath
// `source/`, no product distribution root exists, and the tool build defines
// no install or export surface.
//
// Each check states something that must remain true for as long as `tools/`
// exists. None of them states that the project has not started yet: an audit
// written against the repository's current emptiness passes until the accepted
// Plan is executed and then fails because it was.
[[nodiscard]] Result<ShippingClosureAudit> auditShippingClosure(const std::filesystem::path& repositoryRoot,
                                                                const RepositorySnapshot& snapshot);

} // namespace rawframe::tool::evidence
