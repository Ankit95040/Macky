/**
 * Trusted application registry (M11). Static, administrator-defined:
 * logical IDs bound to absolute bundle + executable paths, every
 * path explicitly verified on this machine (Sequoia layout):
 *
 *   app.textedit   → /System/Applications/TextEdit.app
 *   app.calculator → /System/Applications/Calculator.app
 *   app.terminal   → /System/Applications/Utilities/Terminal.app
 *
 * The planner sees ONLY the logical ID. Registration happens here
 * in trusted code (or via createAppRegistry for deterministic tests)
 * — never from planner input, never by directory scan. Entries are
 * frozen; identity (existence, containment, canonical form,
 * Info.plist presence) is re-verified before EVERY launch.
 */
export interface AppRegistration {
  readonly id: string;
  readonly bundlePath: string;
  readonly executablePath: string;
  readonly displayName: string;
}

function app(
  id: string,
  bundlePath: string,
  executablePath: string,
  displayName: string,
): AppRegistration {
  return Object.freeze({ id, bundlePath, executablePath, displayName });
}

export const PRODUCTION_APPS: ReadonlyArray<AppRegistration> = Object.freeze([
  app(
    "app.textedit",
    "/System/Applications/TextEdit.app",
    "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit",
    "TextEdit",
  ),
  app(
    "app.calculator",
    "/System/Applications/Calculator.app",
    "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
    "Calculator",
  ),
  app(
    "app.terminal",
    "/System/Applications/Utilities/Terminal.app",
    "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
    "Terminal",
  ),
]);

export interface AppRegistry {
  readonly apps: ReadonlyMap<string, AppRegistration>;
}

/** Trusted registry construction (production default or test entries). */
export function createAppRegistry(entries?: ReadonlyArray<AppRegistration>): AppRegistry {
  const map = new Map<string, AppRegistration>();
  for (const entry of entries ?? PRODUCTION_APPS) {
    map.set(entry.id, Object.freeze({ ...entry }));
  }
  return { apps: map };
}

export function lookupApp(registry: AppRegistry, id: string): AppRegistration | undefined {
  return registry.apps.get(id);
}
