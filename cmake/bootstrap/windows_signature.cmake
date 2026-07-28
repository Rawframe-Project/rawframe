include_guard(GLOBAL)

# Owns the locked Windows SDK SignTool identity and the operating-system vendor
# signature check that TASK-0001 resolution R2 requires of serviced inbox
# transport binaries. This lives in the bootstrap layer because Stage 0 must
# admit its transport before the host tuple probe runs. `cmake/sync` includes
# this file rather than restating the SignTool identity.

set(RF_WINDOWS_HOST_SIGNTOOL
    "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe")
set(RF_WINDOWS_HOST_SIGNTOOL_BYTES 543144)
set(RF_WINDOWS_HOST_SIGNTOOL_SHA256
    "e7b517a6a2828af2d1fba3da60ae1e322a95141bfae192622725329630caa2b3")

# Microsoft rotates the leaf certificate that signs inbox binaries long before
# it rotates these roots, so pinning a leaf would reintroduce the recurring
# drift R2 exists to remove. The check binds the trusted root instead, and the
# signature must verify with zero warnings and zero errors.
set(RF_WINDOWS_VENDOR_SIGNATURE_ROOTS
    "Microsoft Root Certificate Authority 2010"
    "Microsoft Root Certificate Authority 2011")

function(rf_verify_windows_vendor_signature primary label)
    rf_verify_file_identity("${RF_WINDOWS_HOST_SIGNTOOL}" "${RF_WINDOWS_HOST_SIGNTOOL_BYTES}"
        "${RF_WINDOWS_HOST_SIGNTOOL_SHA256}" "locked SignTool")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env
            --unset=HTTP_PROXY --unset=HTTPS_PROXY --unset=ALL_PROXY --unset=NO_PROXY
            --unset=http_proxy --unset=https_proxy --unset=all_proxy --unset=no_proxy
            "${RF_WINDOWS_HOST_SIGNTOOL}" verify /pa /v "${primary}"
        RESULT_VARIABLE verify_result OUTPUT_VARIABLE verify_output ERROR_VARIABLE verify_error TIMEOUT 120
    )
    set(verify_text "${verify_output}${verify_error}")
    string(LENGTH "${verify_text}" verify_bytes)
    if(verify_bytes GREATER 1048576)
        rf_bootstrap_fail("RF1441" "vendor signature output exceeded the bounded limit for ${label}")
    endif()

    # Bind the root to the signing chain only. SignTool prints a second chain
    # for the timestamp authority, and accepting a root from that section would
    # let a wrongly rooted signature pass on the strength of its timestamp.
    string(FIND "${verify_text}" "Signing Certificate Chain:" chain_start)
    string(FIND "${verify_text}" "The signature is timestamped" chain_end)
    if(chain_start LESS 0 OR chain_end LESS_EQUAL chain_start)
        rf_bootstrap_fail("RF1443" "vendor signature output has no bounded signing certificate chain for ${label}")
    endif()
    math(EXPR chain_length "${chain_end} - ${chain_start}")
    string(SUBSTRING "${verify_text}" ${chain_start} ${chain_length} signing_chain)

    set(root_matched FALSE)
    foreach(root IN LISTS RF_WINDOWS_VENDOR_SIGNATURE_ROOTS)
        if(signing_chain MATCHES "Issued to: ${root}[\r\n]")
            set(root_matched TRUE)
        endif()
    endforeach()

    if(NOT verify_result EQUAL 0 OR NOT root_matched OR
       NOT verify_text MATCHES "Number of files successfully Verified: 1" OR
       NOT verify_text MATCHES "Number of warnings: 0" OR
       NOT verify_text MATCHES "Number of errors: 0")
        rf_bootstrap_fail("RF1442" "operating-system vendor signature verification failed for ${label}")
    endif()
endfunction()
