/**
 * Copyright (c) 2020 TypeFox GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License-AGPL.txt in the project root for license information.
 */

/**
 * Installs the proxy (shared) worker serving from the same origin to fetch content from the blobserve origin.
 */
export function install(): void {
    if (window.Worker) {
        const Worker = window.Worker;
        window.Worker = <any>function (scriptUrl: string | URL, options?: WorkerOptions) {
            return new Worker(proxyUrl(scriptUrl), options);
        };
    }
    if (window.SharedWorker) {
        const SharedWorker = window.SharedWorker;
        window.SharedWorker = <any>function (scriptUrl: string, options?: string | SharedWorkerOptions) {
            return new SharedWorker(proxyUrl(scriptUrl), options);
        };
    }
}

function proxyUrl(scriptUrl: string | URL): string {
    try {
        scriptUrl = typeof scriptUrl === 'string' ? new URL(scriptUrl) : scriptUrl;
    } catch (e) {
        if (typeof scriptUrl !== 'string') {
            throw e;
        }
        const pathname = scriptUrl;
        scriptUrl = new URL(window.location.href)
        scriptUrl.pathname = pathname;
    }

    if (scriptUrl.protocol === 'data:') {
        return scriptUrl.toString();
    }

    // TODO(ak) importScripts is not going to work for module workers: https://web.dev/module-workers/
    const js = `
(function () {
    var originalImportScripts = self.importScripts;
    self.importScripts = function (scriptUrl) {
        try {
            scriptUrl = new URL(scriptUrl);
        } catch {
            scriptUrl = new URL(scriptUrl, '${scriptUrl}');
        }
        return originalImportScripts(scriptUrl.toString());
    }
    originalImportScripts('${scriptUrl}');
})();
`;
    return `data:text/javascript;charset=utf-8,${encodeURIComponent(js)}`
};
