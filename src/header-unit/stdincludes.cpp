// See https://learn.microsoft.com/en-us/cpp/build/walkthrough-header-units
// https://learn.microsoft.com/en-us/cpp/build/walkthrough-import-stl-header-units
#pragma warning(disable:4005)
#pragma warning(disable:5106)
#pragma warning(disable:4067)
// The above need to be disabled because of
// https://developercommunity.visualstudio.com/t/warning-C4005:-Outptr:-macro-redefinit/1546919
// No idea when this will get fixed, MS seems to be taking their time with it.
import <vector>;
import <string>;
import <source_location>;
import <utility>;
import <memory>;
import <format>;
import <stdexcept>;
import <algorithm>;
import <type_traits>;
import <functional>;
import <iostream>;
import <chrono>;
import <tuple>;
import <sstream>;
import <atomic>;
import <cstdint>;
import <malloc.h>;
import <deque>;
import <map>;
import <filesystem>;
import <optional>;
import <tuple>;
import <future>;
import <ostream>;
import <stacktrace>;
import <ranges>;
