This is a very simple program that calls a Content Decryption Module using
[Google's CDM API](https://chromium.googlesource.com/chromium/cdm/), which is
typically used by Widevine CDMs. It performs all the operations a browser would
perform to play DRM-protected media up until the point communication with a
Widevine license server would be required. It does not continue past that point
and makes no network calls.

Note that `content_decryption_module.h` and `content_decryption_module_export.h`
are copied from Google's API repository above and are not covered by this
project's license.
