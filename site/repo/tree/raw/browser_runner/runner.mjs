import fs from "fs/promises";
import path from "path";
import { chromium } from "playwright";

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const part = argv[i];
    if (!part.startsWith("--")) continue;
    args[part.slice(2)] = argv[i + 1];
    i += 1;
  }
  return args;
}

function classifyError(error) {
  const text = `${error?.message || error || ""}`.toLowerCase();
  if (text.includes("timeout")) return "navigation_timeout";
  if (text.includes("locator") || text.includes("selector") || text.includes("strict mode violation")) {
    return "selector_missing";
  }
  if (text.includes("assert")) return "assertion_failed";
  if (text.includes("net::") || text.includes("connection") || text.includes("dns")) {
    return "network_error";
  }
  if (text.includes("browser")) return "browser_crash";
  return "step_failed";
}

function resolveInputValue(value, secrets) {
  if (value.kind === "literal") return value.value;
  if (value.kind === "secret_ref") {
    const secret = secrets[value.key];
    if (typeof secret !== "string") {
      throw new Error(`missing browser secret ref ${value.key}`);
    }
    return secret;
  }
  throw new Error(`unsupported browser input kind ${value.kind}`);
}

function resolveLocator(page, target) {
  switch (target) {
    case undefined:
      throw new Error("missing browser selector");
    default:
      break;
  }
  if ("css" === target.type || target.kind === "css") {
    return page.locator(target.value);
  }
  if ("text" === target.type || target.kind === "text") {
    return page.getByText(target.value, { exact: false });
  }
  if ("label" === target.type || target.kind === "label") {
    return page.getByLabel(target.value, { exact: false });
  }
  if ("placeholder" === target.type || target.kind === "placeholder") {
    return page.getByPlaceholder(target.value, { exact: false });
  }
  if ("test_id" === target.type || target.kind === "test_id") {
    return page.getByTestId(target.value);
  }
  if ("role" === target.type || target.kind === "role") {
    return page.getByRole(target.role, target.name ? { name: target.name } : {});
  }
  throw new Error(`unsupported browser selector ${JSON.stringify(target)}`);
}

async function writeOutput(outputPath, payload) {
  await fs.writeFile(outputPath, JSON.stringify(payload, null, 2));
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.input || !args.output) {
    throw new Error("runner requires --input and --output");
  }

  const input = JSON.parse(await fs.readFile(args.input, "utf8"));
  await fs.mkdir(input.artifact_dir, { recursive: true });

  const start = Date.now();
  const consoleErrors = [];
  const networkErrors = [];
  const contexts = new Map();
  let currentContextId = "default";
  let failedStepIndex = null;
  let finalUrl = input.package.journey.entry_url;
  let screenshotPath = null;
  let tracePath = null;
  let videoPath = null;
  let outcomeClass = "success";

  const browser = await chromium.launch({ headless: true });

  async function createContext(contextId) {
    const runtime = input.package.runtime;
    const useSessionState =
      runtime.cache_mode === "session_state" &&
      typeof input.session_state_path === "string" &&
      contextId === "default";
    const maybeStorageState = useSessionState ? await fileExists(input.session_state_path) : false;
    const context = await browser.newContext({
      locale: runtime.locale,
      timezoneId: runtime.timezone,
      viewport: {
        width: runtime.viewport_width,
        height: runtime.viewport_height
      },
      colorScheme: runtime.color_scheme === "dark" ? "dark" : "light",
      serviceWorkers: runtime.block_service_workers ? "block" : "allow",
      storageState: maybeStorageState ? input.session_state_path : undefined,
      recordVideo: input.package.artifact_policy.capture_video
        ? { dir: input.artifact_dir, size: { width: runtime.viewport_width, height: runtime.viewport_height } }
        : undefined
    });
    if (input.package.artifact_policy.capture_trace) {
      await context.tracing.start({ screenshots: true, snapshots: true });
    }
    const page = await context.newPage();
    page.on("console", msg => {
      if (msg.type() === "error") {
        consoleErrors.push(msg.text());
      }
    });
    page.on("pageerror", error => {
      consoleErrors.push(String(error));
    });
    page.on("requestfailed", request => {
      const failure = request.failure();
      networkErrors.push(`${request.method()} ${request.url()} ${failure?.errorText || "failed"}`);
    });
    contexts.set(contextId, { context, page });
    return contexts.get(contextId);
  }

  async function ensureCurrentContext() {
    let entry = contexts.get(currentContextId);
    if (!entry) {
      entry = await createContext(currentContextId);
    }
    return entry;
  }

  try {
    await ensureCurrentContext();
    for (let index = 0; index < input.package.journey.steps.length; index += 1) {
      const step = input.package.journey.steps[index];
      const { page, context } = await ensureCurrentContext();
      const timeout = input.package.journey.per_step_timeout_ms;

      try {
        switch (step.kind) {
          case "navigate":
            await page.goto(step.url, { waitUntil: "domcontentloaded", timeout });
            break;
          case "click":
            await resolveLocator(page, step.target).first().click({ timeout });
            break;
          case "fill":
            await resolveLocator(page, step.target)
              .first()
              .fill(resolveInputValue(step.value, input.secrets), { timeout });
            break;
          case "press":
            await page.keyboard.press(step.key);
            break;
          case "wait_for_text":
            await page.getByText(step.text, { exact: false }).waitFor({ state: "visible", timeout });
            break;
          case "assert_text":
            if (!(await page.getByText(step.text, { exact: false }).first().isVisible({ timeout }))) {
              throw new Error(`assertion failed: text not visible: ${step.text}`);
            }
            break;
          case "assert_url_contains":
            if (!page.url().includes(step.text)) {
              throw new Error(`assertion failed: url does not include ${step.text}`);
            }
            break;
          case "capture_screenshot": {
            const label = step.label || `step-${index}`;
            const file = path.join(input.artifact_dir, `${label}.png`);
            await page.screenshot({ path: file, fullPage: true });
            screenshotPath = file;
            break;
          }
          case "open_fresh_context":
            currentContextId = step.context_id;
            await createContext(step.context_id);
            break;
          case "close_context": {
            const entry = contexts.get(step.context_id);
            if (entry) {
              const maybeVideo = entry.page.video();
              if (input.package.artifact_policy.capture_trace) {
                const candidate = path.join(input.artifact_dir, `trace-${step.context_id}.zip`);
                await entry.context.tracing.stop({ path: candidate });
                tracePath = candidate;
              }
              await entry.context.close();
              if (maybeVideo) {
                videoPath = await maybeVideo.path().catch(() => videoPath);
              }
              contexts.delete(step.context_id);
              if (currentContextId === step.context_id) {
                currentContextId = "default";
              }
            }
            break;
          }
          default:
            throw new Error(`unsupported browser step ${step.kind}`);
        }
        finalUrl = page.url();
        void context;
      } catch (error) {
        failedStepIndex = index;
        outcomeClass = classifyError(error);
        if (input.package.artifact_policy.capture_screenshot_on_failure) {
          const file = path.join(input.artifact_dir, `failure-step-${index}.png`);
          await page.screenshot({ path: file, fullPage: true }).catch(() => {});
          screenshotPath = file;
        }
        throw error;
      }
    }

    const defaultEntry = contexts.get("default");
    if (input.package.artifact_policy.capture_trace && defaultEntry) {
      const candidate = path.join(input.artifact_dir, "trace-default.zip");
      await defaultEntry.context.tracing.stop({ path: candidate });
      tracePath = candidate;
    }
    if (
      input.package.runtime.cache_mode === "session_state" &&
      input.package.session_cache.enabled &&
      typeof input.session_state_path === "string" &&
      defaultEntry
    ) {
      await defaultEntry.context.storageState({ path: input.session_state_path });
    }
    for (const [, entry] of contexts) {
      const maybeVideo = entry.page.video();
      await entry.context.close();
      if (!videoPath && maybeVideo) {
        videoPath = await maybeVideo.path().catch(() => videoPath);
      }
    }
    await browser.close();
    await writeOutput(args.output, {
      success: true,
      latency_ms: Date.now() - start,
      failed_step_index: null,
      final_url: finalUrl,
      outcome_class: "success",
      console_error_count: consoleErrors.length,
      network_error_count: networkErrors.length,
      screenshot_path: screenshotPath,
      trace_path: tracePath,
      video_path: videoPath,
      error: null
    });
  } catch (error) {
    for (const [, entry] of contexts) {
      try {
        const maybeVideo = entry.page.video();
        if (input.package.artifact_policy.capture_trace) {
          const candidate = path.join(input.artifact_dir, `trace-${currentContextId}.zip`);
          await entry.context.tracing.stop({ path: candidate }).catch(() => {});
          if (!tracePath) tracePath = candidate;
        }
        await entry.context.close().catch(() => {});
        if (!videoPath && maybeVideo) {
          videoPath = await maybeVideo.path().catch(() => videoPath);
        }
      } catch {
        // ignore cleanup errors
      }
    }
    await browser.close().catch(() => {});
    await writeOutput(args.output, {
      success: false,
      latency_ms: Date.now() - start,
      failed_step_index: failedStepIndex,
      final_url: finalUrl,
      outcome_class: outcomeClass,
      console_error_count: consoleErrors.length,
      network_error_count: networkErrors.length,
      screenshot_path: screenshotPath,
      trace_path: tracePath,
      video_path: videoPath,
      error: String(error?.message || error)
    });
    process.exitCode = 1;
  }
}

async function fileExists(candidate) {
  try {
    await fs.access(candidate);
    return true;
  } catch {
    return false;
  }
}

run().catch(async error => {
  console.error(error);
  process.exit(1);
});
