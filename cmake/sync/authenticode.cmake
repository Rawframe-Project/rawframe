include_guard(GLOBAL)

function(rf_verify_windows_authenticode signtool signtool_bytes signtool_sha256 primary expected_leaf_sha1 label)
    rf_verify_file_identity("${signtool}" "${signtool_bytes}" "${signtool_sha256}" "Windows SDK SignTool")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env
            --unset=HTTP_PROXY --unset=HTTPS_PROXY --unset=ALL_PROXY --unset=NO_PROXY
            --unset=http_proxy --unset=https_proxy --unset=all_proxy --unset=no_proxy
            "${signtool}" verify /pa /all /v /tw "${primary}"
        RESULT_VARIABLE verify_result OUTPUT_VARIABLE verify_output ERROR_VARIABLE verify_error TIMEOUT 120
    )
    string(LENGTH "${verify_output}${verify_error}" verify_bytes)
    string(REGEX MATCHALL "SHA1 hash: ${expected_leaf_sha1}" leaf_matches "${verify_output}${verify_error}")
    list(LENGTH leaf_matches leaf_count)
    if(NOT verify_result EQUAL 0 OR verify_bytes GREATER 1048576 OR NOT leaf_count EQUAL 1 OR
       NOT "${verify_output}${verify_error}" MATCHES "Issued to: Microsoft Corporation" OR
       NOT "${verify_output}${verify_error}" MATCHES "Number of signatures successfully Verified: 1" OR
       NOT "${verify_output}${verify_error}" MATCHES "Number of warnings: 0" OR
       NOT "${verify_output}${verify_error}" MATCHES "Number of errors: 0")
        rf_bootstrap_fail("RF1440" "Authenticode verification failed for ${label}")
    endif()
endfunction()

