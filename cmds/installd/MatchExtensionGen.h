/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/******************************************************************
 * THIS CODE WAS GENERATED BY matchgen.py, DO NOT MODIFY DIRECTLY *
 ******************************************************************/

#include <private/android_filesystem_config.h>

int MatchExtension(const char* ext) {

    switch (ext[0]) {
    case '3':
        switch (ext[1]) {
        case 'g': case 'G':
            switch (ext[2]) {
            case '2':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            case 'p': case 'P':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                case 'p': case 'P':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_VIDEO;
                    case '2':
                        switch (ext[5]) {
                        case '\0': return AID_MEDIA_VIDEO;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 'a': case 'A':
        switch (ext[1]) {
        case 'a': case 'A':
            switch (ext[2]) {
            case 'c': case 'C':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        case 'i': case 'I':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                case 'c': case 'C':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_AUDIO;
                    }
                    break;
                case 'f': case 'F':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_AUDIO;
                    }
                    break;
                }
                break;
            }
            break;
        case 'm': case 'M':
            switch (ext[2]) {
            case 'r': case 'R':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        case 'r': case 'R':
            switch (ext[2]) {
            case 't': case 'T':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            case 'w': case 'W':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 's': case 'S':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            case 'x': case 'X':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        case 'v': case 'V':
            switch (ext[2]) {
            case 'i': case 'I':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        case 'w': case 'W':
            switch (ext[2]) {
            case 'b': case 'B':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        }
        break;
    case 'b': case 'B':
        switch (ext[1]) {
        case 'm': case 'M':
            switch (ext[2]) {
            case 'p': case 'P':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        }
        break;
    case 'c': case 'C':
        switch (ext[1]) {
        case 'r': case 'R':
            switch (ext[2]) {
            case '2':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        }
        break;
    case 'd': case 'D':
        switch (ext[1]) {
        case 'i': case 'I':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        case 'l': case 'L':
            switch (ext[2]) {
            case '\0': return AID_MEDIA_VIDEO;
            }
            break;
        case 'n': case 'N':
            switch (ext[2]) {
            case 'g': case 'G':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'v': case 'V':
            switch (ext[2]) {
            case '\0': return AID_MEDIA_VIDEO;
            }
            break;
        }
        break;
    case 'f': case 'F':
        switch (ext[1]) {
        case 'l': case 'L':
            switch (ext[2]) {
            case 'a': case 'A':
                switch (ext[3]) {
                case 'c': case 'C':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_AUDIO;
                    }
                    break;
                }
                break;
            case 'i': case 'I':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        }
        break;
    case 'g': case 'G':
        switch (ext[1]) {
        case 'i': case 'I':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 's': case 'S':
            switch (ext[2]) {
            case 'm': case 'M':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        }
        break;
    case 'j': case 'J':
        switch (ext[1]) {
        case 'n': case 'N':
            switch (ext[2]) {
            case 'g': case 'G':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'p': case 'P':
            switch (ext[2]) {
            case 'e': case 'E':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                case 'g': case 'G':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_IMAGE;
                    }
                    break;
                }
                break;
            case 'g': case 'G':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        }
        break;
    case 'l': case 'L':
        switch (ext[1]) {
        case 's': case 'S':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            case 'x': case 'X':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        }
        break;
    case 'm': case 'M':
        switch (ext[1]) {
        case '3':
            switch (ext[2]) {
            case 'u': case 'U':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        case '4':
            switch (ext[2]) {
            case 'a': case 'A':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            case 'v': case 'V':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        case 'k': case 'K':
            switch (ext[2]) {
            case 'a': case 'A':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            case 'v': case 'V':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        case 'n': case 'N':
            switch (ext[2]) {
            case 'g': case 'G':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        case 'o': case 'O':
            switch (ext[2]) {
            case 'v': case 'V':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                case 'i': case 'I':
                    switch (ext[4]) {
                    case 'e': case 'E':
                        switch (ext[5]) {
                        case '\0': return AID_MEDIA_VIDEO;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        case 'p': case 'P':
            switch (ext[2]) {
            case '2':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            case '3':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            case '4':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            case 'e': case 'E':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                case 'g': case 'G':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_VIDEO;
                    case 'a': case 'A':
                        switch (ext[5]) {
                        case '\0': return AID_MEDIA_AUDIO;
                        }
                        break;
                    }
                    break;
                }
                break;
            case 'g': case 'G':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                case 'a': case 'A':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_AUDIO;
                    }
                    break;
                }
                break;
            }
            break;
        case 'x': case 'X':
            switch (ext[2]) {
            case 'u': case 'U':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        }
        break;
    case 'n': case 'N':
        switch (ext[1]) {
        case 'e': case 'E':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'r': case 'R':
            switch (ext[2]) {
            case 'w': case 'W':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        }
        break;
    case 'o': case 'O':
        switch (ext[1]) {
        case 'g': case 'G':
            switch (ext[2]) {
            case 'a': case 'A':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            case 'g': case 'G':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        case 'r': case 'R':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        }
        break;
    case 'p': case 'P':
        switch (ext[1]) {
        case 'b': case 'B':
            switch (ext[2]) {
            case 'm': case 'M':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'c': case 'C':
            switch (ext[2]) {
            case 'x': case 'X':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'e': case 'E':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'g': case 'G':
            switch (ext[2]) {
            case 'm': case 'M':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'l': case 'L':
            switch (ext[2]) {
            case 's': case 'S':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        case 'n': case 'N':
            switch (ext[2]) {
            case 'g': case 'G':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            case 'm': case 'M':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'p': case 'P':
            switch (ext[2]) {
            case 'm': case 'M':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 's': case 'S':
            switch (ext[2]) {
            case 'd': case 'D':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        }
        break;
    case 'q': case 'Q':
        switch (ext[1]) {
        case 't': case 'T':
            switch (ext[2]) {
            case '\0': return AID_MEDIA_VIDEO;
            }
            break;
        }
        break;
    case 'r': case 'R':
        switch (ext[1]) {
        case 'a': case 'A':
            switch (ext[2]) {
            case '\0': return AID_MEDIA_AUDIO;
            case 'm': case 'M':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            case 's': case 'S':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'g': case 'G':
            switch (ext[2]) {
            case 'b': case 'B':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'm': case 'M':
            switch (ext[2]) {
            case '\0': return AID_MEDIA_AUDIO;
            }
            break;
        case 'w': case 'W':
            switch (ext[2]) {
            case '2':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        }
        break;
    case 's': case 'S':
        switch (ext[1]) {
        case 'd': case 'D':
            switch (ext[2]) {
            case '2':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        case 'n': case 'N':
            switch (ext[2]) {
            case 'd': case 'D':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        case 'r': case 'R':
            switch (ext[2]) {
            case 'w': case 'W':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'v': case 'V':
            switch (ext[2]) {
            case 'g': case 'G':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                case 'z': case 'Z':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_IMAGE;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 't': case 'T':
        switch (ext[1]) {
        case 'i': case 'I':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                case 'f': case 'F':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_IMAGE;
                    }
                    break;
                }
                break;
            }
            break;
        case 's': case 'S':
            switch (ext[2]) {
            case '\0': return AID_MEDIA_VIDEO;
            }
            break;
        }
        break;
    case 'v': case 'V':
        switch (ext[1]) {
        case 'o': case 'O':
            switch (ext[2]) {
            case 'b': case 'B':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        }
        break;
    case 'w': case 'W':
        switch (ext[1]) {
        case 'a': case 'A':
            switch (ext[2]) {
            case 'v': case 'V':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            case 'x': case 'X':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            }
            break;
        case 'b': case 'B':
            switch (ext[2]) {
            case 'm': case 'M':
                switch (ext[3]) {
                case 'p': case 'P':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_IMAGE;
                    }
                    break;
                }
                break;
            }
            break;
        case 'e': case 'E':
            switch (ext[2]) {
            case 'b': case 'B':
                switch (ext[3]) {
                case 'm': case 'M':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_VIDEO;
                    }
                    break;
                case 'p': case 'P':
                    switch (ext[4]) {
                    case '\0': return AID_MEDIA_IMAGE;
                    }
                    break;
                }
                break;
            }
            break;
        case 'm': case 'M':
            switch (ext[2]) {
            case '\0': return AID_MEDIA_VIDEO;
            case 'a': case 'A':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_AUDIO;
                }
                break;
            case 'v': case 'V':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            case 'x': case 'X':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        case 'r': case 'R':
            switch (ext[2]) {
            case 'f': case 'F':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        case 'v': case 'V':
            switch (ext[2]) {
            case 'x': case 'X':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_VIDEO;
                }
                break;
            }
            break;
        }
        break;
    case 'x': case 'X':
        switch (ext[1]) {
        case 'b': case 'B':
            switch (ext[2]) {
            case 'm': case 'M':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'p': case 'P':
            switch (ext[2]) {
            case 'm': case 'M':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        case 'w': case 'W':
            switch (ext[2]) {
            case 'd': case 'D':
                switch (ext[3]) {
                case '\0': return AID_MEDIA_IMAGE;
                }
                break;
            }
            break;
        }
        break;
    }

    return 0;
}
