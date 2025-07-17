/*
AKRODLABS iOS Frida Instrumentation Script
Comprehensive iOS malware analysis hooks
*/

console.log("[*] AKRODLABS iOS Analysis Script Starting...");

if (ObjC.available) {
    console.log("[*] Objective-C runtime available, setting up hooks...");
    
    // Hook NSURLSession for network monitoring
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        if (NSURLSession) {
            var dataTaskWithRequest = NSURLSession['- dataTaskWithRequest:completionHandler:'];
            Interceptor.attach(dataTaskWithRequest.implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[2]);
                    var url = request.URL();
                    console.log("[HTTP] NSURLSession request to: " + url.toString());
                }
            });
            console.log("[+] NSURLSession hooks installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook NSURLSession: " + e);
    }
    
    // Hook location services
    try {
        var CLLocationManager = ObjC.classes.CLLocationManager;
        if (CLLocationManager) {
            var startUpdatingLocation = CLLocationManager['- startUpdatingLocation'];
            Interceptor.attach(startUpdatingLocation.implementation, {
                onEnter: function(args) {
                    console.log("[LOCATION] Starting location updates");
                    var manager = new ObjC.Object(args[0]);
                    console.log("[LOCATION] Manager: " + manager.toString());
                }
            });
            
            var requestWhenInUseAuthorization = CLLocationManager['- requestWhenInUseAuthorization'];
            Interceptor.attach(requestWhenInUseAuthorization.implementation, {
                onEnter: function(args) {
                    console.log("[LOCATION] Requesting location permission");
                }
            });
            console.log("[+] Location services hooks installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook location services: " + e);
    }
    
    // Hook keychain operations
    try {
        var SecItemAdd = new NativeFunction(
            Module.findExportByName('Security', 'SecItemAdd'),
            'int', ['pointer', 'pointer']
        );
        
        var SecItemCopyMatching = new NativeFunction(
            Module.findExportByName('Security', 'SecItemCopyMatching'),
            'int', ['pointer', 'pointer']
        );
        
        Interceptor.replace(SecItemAdd, new NativeCallback(function(attributes, result) {
            console.log("[KEYCHAIN] Adding item to keychain");
            return SecItemAdd(attributes, result);
        }, 'int', ['pointer', 'pointer']));
        
        Interceptor.replace(SecItemCopyMatching, new NativeCallback(function(query, result) {
            console.log("[KEYCHAIN] Accessing keychain item");
            return SecItemCopyMatching(query, result);
        }, 'int', ['pointer', 'pointer']));
        
        console.log("[+] Keychain hooks installed");
    } catch (e) {
        console.log("[-] Failed to hook keychain operations: " + e);
    }
    
    // Hook contacts access
    try {
        var CNContactStore = ObjC.classes.CNContactStore;
        if (CNContactStore) {
            var requestAccessForEntityType = CNContactStore['- requestAccessForEntityType:completionHandler:'];
            Interceptor.attach(requestAccessForEntityType.implementation, {
                onEnter: function(args) {
                    console.log("[CONTACTS] Requesting contacts access");
                }
            });
            
            var unifiedContactsMatchingPredicate = CNContactStore['- unifiedContactsMatchingPredicate:keysToFetch:error:'];
            Interceptor.attach(unifiedContactsMatchingPredicate.implementation, {
                onEnter: function(args) {
                    console.log("[CONTACTS] Fetching contacts data");
                }
            });
            console.log("[+] Contacts hooks installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook contacts access: " + e);
    }
    
    // Hook file operations
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        if (NSFileManager) {
            var createFileAtPath = NSFileManager['- createFileAtPath:contents:attributes:'];
            Interceptor.attach(createFileAtPath.implementation, {
                onEnter: function(args) {
                    var path = new ObjC.Object(args[2]);
                    console.log("[FILE] Creating file at: " + path.toString());
                }
            });
            
            var removeItemAtPath = NSFileManager['- removeItemAtPath:error:'];
            Interceptor.attach(removeItemAtPath.implementation, {
                onEnter: function(args) {
                    var path = new ObjC.Object(args[2]);
                    console.log("[FILE] Removing file at: " + path.toString());
                }
            });
            console.log("[+] File operation hooks installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook file operations: " + e);
    }
    
    // Hook messages/SMS (if available)
    try {
        var MFMessageComposeViewController = ObjC.classes.MFMessageComposeViewController;
        if (MFMessageComposeViewController) {
            console.log("[+] Message compose controller monitoring prepared");
        }
    } catch (e) {
        console.log("[-] Failed to hook message operations: " + e);
    }
    
    // Hook Touch ID / Face ID
    try {
        var LAContext = ObjC.classes.LAContext;
        if (LAContext) {
            var evaluatePolicy = LAContext['- evaluatePolicy:localizedReason:reply:'];
            Interceptor.attach(evaluatePolicy.implementation, {
                onEnter: function(args) {
                    var reason = new ObjC.Object(args[3]);
                    console.log("[BIOMETRIC] Biometric authentication requested: " + reason.toString());
                }
            });
            console.log("[+] Biometric authentication hooks installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook biometric authentication: " + e);
    }
    
    // Hook camera access
    try {
        var AVCaptureSession = ObjC.classes.AVCaptureSession;
        if (AVCaptureSession) {
            var startRunning = AVCaptureSession['- startRunning'];
            Interceptor.attach(startRunning.implementation, {
                onEnter: function(args) {
                    console.log("[CAMERA] Camera session started");
                }
            });
            console.log("[+] Camera access hooks installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook camera access: " + e);
    }
    
    // Hook microphone access
    try {
        var AVAudioSession = ObjC.classes.AVAudioSession;
        if (AVAudioSession) {
            var setActive = AVAudioSession['- setActive:error:'];
            Interceptor.attach(setActive.implementation, {
                onEnter: function(args) {
                    console.log("[MICROPHONE] Audio session activated");
                }
            });
            console.log("[+] Microphone access hooks installed");
        }
    } catch (e) {
        console.log("[-] Failed to hook microphone access: " + e);
    }
    
} else {
    console.log("[-] Objective-C runtime not available");
}

// Hook some common C functions
try {
    var fopen = Module.findExportByName(null, "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                var filename = Memory.readUtf8String(args[0]);
                var mode = Memory.readUtf8String(args[1]);
                console.log("[NATIVE] Opening file: " + filename + " (mode: " + mode + ")");
            }
        });
    }
    
    var dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function(args) {
                var library = Memory.readUtf8String(args[0]);
                console.log("[NATIVE] Loading library: " + library);
            }
        });
    }
    console.log("[+] Native function hooks installed");
} catch (e) {
    console.log("[-] Failed to hook native functions: " + e);
}

console.log("[*] All hooks installed. Monitoring iOS app behavior...");
