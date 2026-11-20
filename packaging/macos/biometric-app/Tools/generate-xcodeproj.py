#!/usr/bin/env python3
"""生成 KeyKoiBiometric.xcodeproj/project.pbxproj 与共享 scheme。

本机没有 xcodegen，所以工程文件由这个脚本确定性生成：ID 固定，重复运行得到同样的
字节。想用 xcodegen 的机器可以直接 `xcodegen generate` 读同目录的 project.yml。

用法：
  python3 Tools/generate-xcodeproj.py            # 生成/覆盖工程
  python3 Tools/generate-xcodeproj.py --check    # 只校验现有工程是否最新
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = os.path.join(ROOT, "KeyKoiBiometric.xcodeproj")
PBXPROJ = os.path.join(PROJECT_DIR, "project.pbxproj")
SCHEME = os.path.join(PROJECT_DIR, "xcshareddata", "xcschemes", "KeyKoiBiometric.xcscheme")

TEAM = "977QNJU6V6"
BUNDLE_ID = "com.keykoi.biometric"
PRODUCT_NAME = "KeyKoi Biometric"
EXECUTABLE = "keykoi-biometric"
DEPLOYMENT_TARGET = "13.0"

IDS = {
    "project": "AA0000000000000000000001",
    "main_group": "AA0000000000000000000002",
    "app_group": "AA0000000000000000000003",
    "products_group": "AA0000000000000000000004",
    "info_plist": "AA0000000000000000000005",
    "entitlements": "AA0000000000000000000006",
    "swift_src": "AA0000000000000000000007",
    "app_product": "AA0000000000000000000008",
    "target": "AA0000000000000000000009",
    "build_file": "AA000000000000000000000A",

    "sources_phase": "AA000000000000000000000B",
    "frameworks_phase": "AA000000000000000000000C",
    "resources_phase": "AA000000000000000000000D",
    "project_cfg_list": "AA000000000000000000000E",
    "target_cfg_list": "AA000000000000000000000F",
    "project_release": "AA0000000000000000000010",
    "project_debug": "AA0000000000000000000011",
    "target_release": "AA0000000000000000000012",
    "target_debug": "AA0000000000000000000013",
}


def project_build_settings(debug):
    common = """\
				ALWAYS_SEARCH_USER_PATHS = NO;
				CLANG_ENABLE_MODULES = YES;
				CLANG_ENABLE_OBJC_ARC = YES;
				CODE_SIGN_STYLE = Automatic;
				COPY_PHASE_STRIP = NO;
				DEAD_CODE_STRIPPING = YES;
				DEVELOPMENT_TEAM = %s;
				ENABLE_STRICT_OBJC_MSGSEND = YES;
				GCC_C_LANGUAGE_STANDARD = gnu17;
				MACOSX_DEPLOYMENT_TARGET = %s;
				SDKROOT = macosx;
				SWIFT_VERSION = 5.0;
""" % (TEAM, DEPLOYMENT_TARGET)
    if debug:
        return common + """\
				DEBUG_INFORMATION_FORMAT = dwarf;
				ENABLE_TESTABILITY = YES;
				GCC_OPTIMIZATION_LEVEL = 0;
				ONLY_ACTIVE_ARCH = YES;
				SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
"""
    return common + """\
				DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";
				ENABLE_NS_ASSERTIONS = NO;
				SWIFT_COMPILATION_MODE = wholemodule;
				SWIFT_OPTIMIZATION_LEVEL = "-O";
"""


def target_build_settings(debug):
    return """\
				CODE_SIGN_ENTITLEMENTS = App/KeyKoiBiometric.entitlements;
				CODE_SIGN_IDENTITY = "Apple Development";
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = %s;
				ENABLE_APP_SANDBOX = NO;
				ENABLE_HARDENED_RUNTIME = YES;
				EXECUTABLE_NAME = %s;
				GENERATE_INFOPLIST_FILE = NO;
				INFOPLIST_FILE = App/Info.plist;
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/../Frameworks",
				);
				MARKETING_VERSION = 0.1.0;
				PRODUCT_BUNDLE_IDENTIFIER = %s;
				PRODUCT_NAME = "%s";
				PROVISIONING_PROFILE_SPECIFIER = "";
				SWIFT_EMIT_LOC_STRINGS = NO;
				SWIFT_VERSION = 5.0;
""" % (TEAM, EXECUTABLE, BUNDLE_ID, PRODUCT_NAME)


PBXPROJ_TEMPLATE = """\
// !$*UTF8*$!
{{
	archiveVersion = 1;
	classes = {{
	}};
	objectVersion = 56;
	objects = {{

/* Begin PBXBuildFile section */
		{build_file} /* keykoi-biometric.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {swift_src} /* keykoi-biometric.swift */; }};
/* End PBXBuildFile section */

/* Begin PBXFileReference section */
		{info_plist} /* Info.plist */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = "<group>"; }};
		{entitlements} /* KeyKoiBiometric.entitlements */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.entitlements; path = KeyKoiBiometric.entitlements; sourceTree = "<group>"; }};
		{swift_src} /* keykoi-biometric.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = "keykoi-biometric.swift"; path = "../keykoi-biometric.swift"; sourceTree = "<group>"; }};
		{app_product} /* {product_name}.app */ = {{isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = "{product_name}.app"; sourceTree = BUILT_PRODUCTS_DIR; }};
/* End PBXFileReference section */

/* Begin PBXFrameworksBuildPhase section */
		{frameworks_phase} /* Frameworks */ = {{
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
/* End PBXFrameworksBuildPhase section */

/* Begin PBXGroup section */
		{main_group} = {{
			isa = PBXGroup;
			children = (
				{swift_src} /* keykoi-biometric.swift */,
				{app_group} /* App */,
				{products_group} /* Products */,
			);
			sourceTree = "<group>";
		}};
		{app_group} /* App */ = {{
			isa = PBXGroup;
			children = (
				{info_plist} /* Info.plist */,
				{entitlements} /* KeyKoiBiometric.entitlements */,
			);
			path = App;
			sourceTree = "<group>";
		}};
		{products_group} /* Products */ = {{
			isa = PBXGroup;
			children = (
				{app_product} /* {product_name}.app */,
			);
			name = Products;
			sourceTree = "<group>";
		}};
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
		{target} /* KeyKoiBiometric */ = {{
			isa = PBXNativeTarget;
			buildConfigurationList = {target_cfg_list} /* Build configuration list for PBXNativeTarget "KeyKoiBiometric" */;
			buildPhases = (
				{sources_phase} /* Sources */,
				{frameworks_phase} /* Frameworks */,
				{resources_phase} /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
			);
			name = KeyKoiBiometric;
			productName = "{product_name}";
			productReference = {app_product} /* {product_name}.app */;
			productType = "com.apple.product-type.application";
		}};
/* End PBXNativeTarget section */

/* Begin PBXProject section */
		{project} /* Project object */ = {{
			isa = PBXProject;
			attributes = {{
				BuildIndependentTargetsInParallel = 1;
				LastUpgradeCheck = 1600;
				TargetAttributes = {{
					{target} = {{
						CreatedOnToolsVersion = 16.0;
						DevelopmentTeam = {team};
					}};
				}};
			}};
			buildConfigurationList = {project_cfg_list} /* Build configuration list for PBXProject "KeyKoiBiometric" */;
			compatibilityVersion = "Xcode 14.0";
			developmentRegion = en;
			hasScannedForEncodings = 0;
			knownRegions = (
				en,
				Base,
			);
			mainGroup = {main_group};
			productRefGroup = {products_group} /* Products */;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				{target} /* KeyKoiBiometric */,
			);
		}};
/* End PBXProject section */

/* Begin PBXResourcesBuildPhase section */
		{resources_phase} /* Resources */ = {{
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
/* End PBXResourcesBuildPhase section */

/* Begin PBXSourcesBuildPhase section */
		{sources_phase} /* Sources */ = {{
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
				{build_file} /* keykoi-biometric.swift in Sources */,
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
/* End PBXSourcesBuildPhase section */

/* Begin XCBuildConfiguration section */
		{project_debug} /* Debug */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{
{project_debug_settings}\
			}};
			name = Debug;
		}};
		{project_release} /* Release */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{
{project_release_settings}\
			}};
			name = Release;
		}};
		{target_debug} /* Debug */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{
{target_debug_settings}\
			}};
			name = Debug;
		}};
		{target_release} /* Release */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{
{target_release_settings}\
			}};
			name = Release;
		}};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
		{project_cfg_list} /* Build configuration list for PBXProject "KeyKoiBiometric" */ = {{
			isa = XCConfigurationList;
			buildConfigurations = (
				{project_debug} /* Debug */,
				{project_release} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		}};
		{target_cfg_list} /* Build configuration list for PBXNativeTarget "KeyKoiBiometric" */ = {{
			isa = XCConfigurationList;
			buildConfigurations = (
				{target_debug} /* Debug */,
				{target_release} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		}};
/* End XCConfigurationList section */
	}};
	rootObject = {project} /* Project object */;
}}
"""

SCHEME_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<Scheme
   LastUpgradeVersion = "1600"
   version = "1.7">
   <BuildAction
      parallelizeBuildables = "YES"
      buildImplicitDependencies = "YES">
      <BuildActionEntries>
         <BuildActionEntry
            buildForTesting = "YES"
            buildForRunning = "YES"
            buildForProfiling = "YES"
            buildForArchiving = "YES"
            buildForAnalyzing = "YES">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "{target}"
               BuildableName = "{product_name}.app"
               BlueprintName = "KeyKoiBiometric"
               ReferencedContainer = "container:KeyKoiBiometric.xcodeproj">
            </BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <TestAction
      buildConfiguration = "Debug"
      selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB"
      selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB"
      shouldUseLaunchSchemeArgsEnv = "YES">
      <Testables>
      </Testables>
   </TestAction>
   <LaunchAction
      buildConfiguration = "Debug"
      selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB"
      selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB"
      launchStyle = "0"
      useCustomWorkingDirectory = "NO"
      ignoresPersistentStateOnLaunch = "NO"
      debugDocumentVersioning = "YES"
      debugServiceExtension = "internal"
      allowLocationSimulation = "YES">
      <BuildableProductRunnable
         runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "{target}"
            BuildableName = "{product_name}.app"
            BlueprintName = "KeyKoiBiometric"
            ReferencedContainer = "container:KeyKoiBiometric.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </LaunchAction>
   <ProfileAction
      buildConfiguration = "Release"
      shouldUseLaunchSchemeArgsEnv = "YES"
      savedToolIdentifier = ""
      useCustomWorkingDirectory = "NO"
      debugDocumentVersioning = "YES">
      <BuildableProductRunnable
         runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "{target}"
            BuildableName = "{product_name}.app"
            BlueprintName = "KeyKoiBiometric"
            ReferencedContainer = "container:KeyKoiBiometric.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </ProfileAction>
   <AnalyzeAction
      buildConfiguration = "Debug">
   </AnalyzeAction>
   <ArchiveAction
      buildConfiguration = "Release"
      revealArchiveInOrganizer = "YES">
   </ArchiveAction>
</Scheme>
"""


def render():
    pbx = PBXPROJ_TEMPLATE.format(
        project_debug_settings=project_build_settings(True),
        project_release_settings=project_build_settings(False),
        target_debug_settings=target_build_settings(True),
        target_release_settings=target_build_settings(False),
        team=TEAM,
        product_name=PRODUCT_NAME,
        **IDS,
    )
    scheme = SCHEME_TEMPLATE.format(target=IDS["target"], product_name=PRODUCT_NAME)
    return pbx, scheme


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="只在工程过期时以非零退出码报告")
    args = parser.parse_args()

    pbx, scheme = render()
    files = {PBXPROJ: pbx, SCHEME: scheme}

    if args.check:
        stale = [p for p, body in files.items() if not os.path.exists(p) or open(p).read() != body]
        if stale:
            print("stale: " + ", ".join(stale))
            return 1
        print("xcodeproj up to date")
        return 0

    for path, body in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write(body)
        print("wrote " + os.path.relpath(path, ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
