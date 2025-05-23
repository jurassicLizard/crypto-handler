include(FetchContent)


FetchContent_Declare(
        byte-ao
        GIT_REPOSITORY https://github.com/jurassicLizard/byte-ao.git
        GIT_TAG master
        UPDATE_COMMAND ${GIT_EXECUTABLE} pull
)

# Make it available
FetchContent_MakeAvailable(byte-ao)