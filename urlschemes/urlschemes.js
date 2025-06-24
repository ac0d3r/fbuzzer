const {
    LSApplicationWorkspace,
    NSFileManager,
    NSDictionary
} = ObjC.classes;

function listall() {
    const apps = [];
    const workspace = LSApplicationWorkspace.defaultWorkspace();
    const iapps = workspace.allInstalledApplications();

    for (let i = 0; i < iapps.count(); i++) {
        const proxy = iapps.objectAtIndex_(i);
        const bundleID = proxy.bundleIdentifier().toString();
        const bundleURL = proxy.bundleURL();
        const appPath = bundleURL ? bundleURL.path().toString() : "unknown";

        const infoPlistPath = appPath + "/Info.plist";
        const fileManager = NSFileManager.defaultManager();
        let appName = "Unknown";
        const schemes = [];

        if (fileManager.fileExistsAtPath_(infoPlistPath)) {
            const dict = NSDictionary.dictionaryWithContentsOfFile_(infoPlistPath);
            if (dict) {
                const nameObj = dict.objectForKey_("CFBundleName");
                if (nameObj) {
                    appName = nameObj.toString();
                }

                const urlTypes = dict.objectForKey_("CFBundleURLTypes");
                if (urlTypes) {
                    for (let j = 0; j < urlTypes.count(); j++) {
                        const urlSchemes = urlTypes.objectAtIndex_(j).
                            objectForKey_("CFBundleURLSchemes");
                        if (urlSchemes) {
                            for (let k = 0; k < urlSchemes.count(); k++) {
                                schemes.push(urlSchemes.objectAtIndex_(k).toString());
                            }
                        }
                    }
                }
            }
        }
        if (schemes.length > 0) {
            apps.push({
                name: appName,
                id: bundleID,
                path: appPath,
                urlSchemes: schemes
            });
        }
    }

    return apps;
}

try {
    const apps = listall();
    apps.forEach((app, index) => {
        console.log(`\n[${index + 1}] ${app.name} (${app.id})`);
        console.log(`   Path: ${app.path}`);
        console.log(`   URL Schemes: ${app.urlSchemes.join(', ')}`);
    });
} catch (error) {
    console.error(error.stack);
}
