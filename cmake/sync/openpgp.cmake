include_guard(GLOBAL)

function(rf_prepare_release_keyring gpg gpgconf key_file expected_primary work_root token output_keyring)
    set(home "${work_root}/${token}-gnupg-home")
    set(keyring "${work_root}/${token}-release-keyring.gpg")
    file(REMOVE_RECURSE "${home}")
    file(REMOVE "${keyring}")
    file(MAKE_DIRECTORY "${home}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env --unset=GNUPGHOME --unset=GPG_AGENT_INFO
            "${gpg}" --batch --no-options --homedir "${home}" --import "${key_file}"
        RESULT_VARIABLE import_result OUTPUT_VARIABLE import_output ERROR_VARIABLE import_error TIMEOUT 30
    )
    string(LENGTH "${import_output}${import_error}" import_bytes)
    if(NOT import_result EQUAL 0 OR import_bytes GREATER 524288)
        rf_bootstrap_fail("RF1430" "release-key import failed for ${token}")
    endif()
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env --unset=GNUPGHOME --unset=GPG_AGENT_INFO
            "${gpg}" --batch --no-options --homedir "${home}" --with-colons --fingerprint "${expected_primary}"
        RESULT_VARIABLE fingerprint_result OUTPUT_VARIABLE fingerprint_output ERROR_VARIABLE fingerprint_error TIMEOUT 15
    )
    string(REGEX MATCHALL "fpr:::::::::${expected_primary}:" fingerprint_matches "${fingerprint_output}")
    list(LENGTH fingerprint_matches fingerprint_count)
    if(NOT fingerprint_result EQUAL 0 OR NOT fingerprint_count EQUAL 1)
        rf_bootstrap_fail("RF1431" "exact release primary key is absent or ambiguous for ${token}")
    endif()
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env --unset=GNUPGHOME --unset=GPG_AGENT_INFO
            "${gpg}" --batch --no-options --homedir "${home}" --export "${expected_primary}"
        RESULT_VARIABLE export_result OUTPUT_FILE "${keyring}" ERROR_VARIABLE export_error TIMEOUT 15
    )
    if(NOT export_result EQUAL 0 OR NOT EXISTS "${keyring}")
        rf_bootstrap_fail("RF1432" "cannot create isolated release keyring for ${token}")
    endif()
    rf_shutdown_gnupg_home("${gpgconf}" "${home}")
    set(${output_keyring} "${keyring}" PARENT_SCOPE)
endfunction()

function(rf_verify_detached_openpgp gpgv keyring signature primary expected_signer label)
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env --unset=GNUPGHOME --unset=GPG_AGENT_INFO
            "${gpgv}" --status-fd=1 --keyring "${keyring}" "${signature}" "${primary}"
        RESULT_VARIABLE verify_result OUTPUT_VARIABLE verify_output ERROR_VARIABLE verify_error TIMEOUT 180
    )
    string(LENGTH "${verify_output}${verify_error}" verify_bytes)
    string(REGEX MATCHALL "VALIDSIG ${expected_signer} " valid_matches "${verify_output}")
    list(LENGTH valid_matches valid_count)
    if(NOT verify_result EQUAL 0 OR verify_bytes GREATER 524288 OR NOT valid_count EQUAL 1)
        rf_bootstrap_fail("RF1433" "detached OpenPGP verification failed for ${label}")
    endif()
endfunction()

function(rf_require_exact_checksum_line checksums expected_line label)
    file(SIZE "${checksums}" checksum_bytes)
    if(checksum_bytes GREATER 1048576)
        rf_bootstrap_fail("RF1434" "checksum authority exceeds limit for ${label}")
    endif()
    file(READ "${checksums}" content LIMIT 1048577)
    string(REPLACE "\r" "" content "${content}")
    string(REPLACE "\n" ";" lines "${content}")
    set(matches 0)
    foreach(line IN LISTS lines)
        if(line STREQUAL expected_line)
            math(EXPR matches "${matches} + 1")
        endif()
    endforeach()
    if(NOT matches EQUAL 1)
        rf_bootstrap_fail("RF1435" "signed checksum does not bind ${label} exactly once")
    endif()
endfunction()

