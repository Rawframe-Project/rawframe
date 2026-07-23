include_guard(GLOBAL)

function(rf_classify_https_url url origin_host is_redirect output_host)
    if(url MATCHES "#" OR url MATCHES "^https://[^/]*@")
        rf_bootstrap_fail("RF1240" "transport URL contains forbidden credentials or fragment")
    endif()
    if(NOT url MATCHES "^https://([^/?#]+)(/[^#]*)?$")
        rf_bootstrap_fail("RF1241" "transport URL is not an absolute HTTPS URL")
    endif()
    set(authority "${CMAKE_MATCH_1}")
    if(authority MATCHES ":")
        rf_bootstrap_fail("RF1242" "transport URL contains a non-default or ambiguous port")
    endif()
    string(TOLOWER "${authority}" host)

    if(NOT is_redirect)
        if(url MATCHES "\\?")
            rf_bootstrap_fail("RF1243" "authoritative origin must be query-free")
        endif()
        set(admitted_origins github.com www.sourcemeta.com www.nasm.us www.nasm.dev releases.ubuntu.com archive.ubuntu.com gnupg.org files.gpg4win.org download.nus.edu.sg tuf-repo-cdn.sigstore.dev releases.llvm.org packages.microsoft.com openssl-library.org)
        list(FIND admitted_origins "${host}" admitted_index)
        if(admitted_index EQUAL -1)
            rf_bootstrap_fail("RF1244" "authoritative origin host is not allowlisted")
        endif()
    else()
        if(NOT origin_host STREQUAL "github.com")
            rf_bootstrap_fail("RF1245" "non-GitHub authority attempted a redirect")
        endif()
        set(github_redirect_hosts github.com release-assets.githubusercontent.com codeload.github.com)
        list(FIND github_redirect_hosts "${host}" admitted_index)
        if(admitted_index EQUAL -1)
            rf_bootstrap_fail("RF1246" "GitHub redirect target host is not allowlisted")
        endif()
        if(url MATCHES "\\?" AND NOT host STREQUAL "release-assets.githubusercontent.com")
            rf_bootstrap_fail("RF1247" "query string is forbidden on this redirect host")
        endif()
    endif()
    set(${output_host} "${host}" PARENT_SCOPE)
endfunction()

function(rf_verify_transport_executable executable expected_version expected_bytes expected_sha256)
    rf_verify_file_identity("${executable}" "${expected_bytes}" "${expected_sha256}" "bootstrap transport")
    execute_process(
        COMMAND "${executable}" -q --version
        RESULT_VARIABLE version_result
        OUTPUT_VARIABLE version_output
        ERROR_VARIABLE version_error
        TIMEOUT 10
    )
    if(NOT version_result EQUAL 0 OR NOT version_output MATCHES "^curl ${expected_version} ")
        rf_bootstrap_fail("RF1248" "bootstrap transport version identity mismatch")
    endif()
endfunction()

function(rf_download_manually_redirected curl_executable origin destination expected_bytes output_hops output_hosts)
    rf_classify_https_url("${origin}" "" FALSE origin_host)
    set(current_url "${origin}")
    set(redirect_count 0)
    set(host_classes "${origin_host}")
    set(hop_file "${destination}.hop")

    while(TRUE)
        file(REMOVE "${hop_file}")
        execute_process(
            COMMAND "${CMAKE_COMMAND}" -E env
                --unset=HTTP_PROXY --unset=HTTPS_PROXY --unset=ALL_PROXY --unset=NO_PROXY
                --unset=http_proxy --unset=https_proxy --unset=all_proxy --unset=no_proxy
                --unset=CURL_HOME --unset=NETRC
                "${curl_executable}"
                -q --silent --show-error --no-progress-meter
                --proto "=https" --tlsv1.2 --connect-timeout 10 --max-time 1800
                --max-redirs 0 --disallow-username-in-url --proxy "" --noproxy "*"
                --max-filesize "${expected_bytes}" --output "${hop_file}"
                --write-out "RF_STATUS:%{response_code}\nRF_REDIRECT:%{redirect_url}"
                --url "${current_url}"
            RESULT_VARIABLE transfer_result
            OUTPUT_VARIABLE transfer_metadata
            ERROR_VARIABLE transfer_error
            TIMEOUT 1810
        )
        unset(current_url)
        if(NOT transfer_result EQUAL 0)
            file(REMOVE "${hop_file}")
            rf_bootstrap_fail("RF1249" "HTTPS transport failed with sanitized curl status ${transfer_result}")
        endif()
        string(REPLACE "\r" "" transfer_metadata "${transfer_metadata}")
        if(NOT transfer_metadata MATCHES "^RF_STATUS:([0-9][0-9][0-9])\nRF_REDIRECT:(.*)$")
            file(REMOVE "${hop_file}")
            rf_bootstrap_fail("RF1250" "HTTPS transport returned malformed bounded metadata")
        endif()
        set(status_code "${CMAKE_MATCH_1}")
        set(redirect_url "${CMAKE_MATCH_2}")

        if(status_code GREATER_EQUAL 200 AND status_code LESS 300)
            if(NOT redirect_url STREQUAL "")
                file(REMOVE "${hop_file}")
                rf_bootstrap_fail("RF1251" "successful HTTPS response carried unexpected redirect metadata")
            endif()
            file(RENAME "${hop_file}" "${destination}" RESULT rename_result)
            if(NOT rename_result STREQUAL "0")
                file(REMOVE "${hop_file}")
                rf_bootstrap_fail("RF1252" "cannot publish transport result into quarantine")
            endif()
            break()
        endif()

        if(status_code GREATER_EQUAL 300 AND status_code LESS 400 AND NOT redirect_url STREQUAL "")
            file(REMOVE "${hop_file}")
            if(redirect_count GREATER_EQUAL 3)
                unset(redirect_url)
                rf_bootstrap_fail("RF1253" "HTTPS redirect limit exceeded")
            endif()
            rf_classify_https_url("${redirect_url}" "${origin_host}" TRUE redirect_host)
            math(EXPR redirect_count "${redirect_count} + 1")
            list(APPEND host_classes "${redirect_host}")
            set(current_url "${redirect_url}")
            unset(redirect_url)
            continue()
        endif()

        file(REMOVE "${hop_file}")
        unset(redirect_url)
        rf_bootstrap_fail("RF1254" "HTTPS transport returned status class ${status_code}")
    endwhile()

    set(${output_hops} "${redirect_count}" PARENT_SCOPE)
    set(${output_hosts} "${host_classes}" PARENT_SCOPE)
endfunction()
