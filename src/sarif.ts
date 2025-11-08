import { readFileSync, writeFileSync } from 'fs';
import { Result } from 'sarif';
import {
    SarifBuilder,
    SarifRunBuilder,
    SarifResultBuilder,
} from 'node-sarif-builder';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

export function minVal(val: number) {
    if (val) {
        return val;
    }
    return 1;
}

export function relative(rootdir: string, fullpath: string) {
    if (rootdir) {
        if (fullpath.toLowerCase().startsWith(rootdir.toLowerCase())) {
            return fullpath.substring(rootdir.length);
        }
    }
    return fullpath;
}

const options = {
    filename: {
        type: 'string',
        demandOption: true,
        describe: 'Input filename',
    },
    output: {
        type: 'string',
        demandOption: false,
        describe: 'Output filename',
    },
    root: {
        type: 'string',
        demandOption: false,
        describe: 'Root directory',
    },
} as const;

export function main() {
    const argv = yargs(hideBin(process.argv))
        .usage('Usage: $0 <inputfile> [options]')
        .options(options)
        .help()
        .parseSync();

    exportSarif(argv.filename, argv.output, argv.root);
}

export interface Via {
    source: number;
    name: string;
    dependency: string;
    title: string;
    url: string;
    severity: string;
    cwe: string[];
}

export interface Vulnerability {
    name: string;
    severity: string;
    via: Via[] | string[];
    isDirect: boolean;
    range: string;
    fixAvailable: boolean;
}

export function exportSarif(
    filename: string,
    outputfilename: string,
    rootdir: string
) {
    const results = JSON.parse(readFileSync(filename, 'utf8'));

    // SARIF builder
    const sarifBuilder = new SarifBuilder();

    // SARIF Run builder
    const sarifRunBuilder = new SarifRunBuilder().initSimple({
        toolDriverName: 'npm-audit-sarif',
        toolDriverVersion: '0.1.0',
    });

    for (const key in results.vulnerabilities) {
        const value = results.vulnerabilities[key];

        for (const viaobj of value.via) {
            if (typeof viaobj == 'string') {
                continue;
            }
            const via: Via = viaobj as Via;
            let msg =
                'Audit: ' +
                via.severity +
                '\n' +
                via.name +
                '\n' +
                via.title +
                '\n' +
                via.url;

            if (via.cwe.length) {
                for (const cwe of via.cwe) {
                    msg += '\n';
                    msg += cwe;
                }
            }

            // Map npm audit severities to SARIF allowed levels: none, note, warning, error
            let level: Result.level = 'note';
            const sev = (via.severity || '').toLowerCase();
            switch (sev) {
                case 'low':
                    level = 'note';
                    break;
                case 'moderate':
                    level = 'warning';
                    break;
                case 'high':
                    level = 'warning';
                    break;
                case 'critical':
                    level = 'error';
                    break;
                default:
                    // fallback to note for unknown severities
                    level = 'note';
            }

            const ruleId =
                'npm-audit-' +
                key.toLowerCase().replaceAll('_', '-').replaceAll(' ', '-');

            const sarifResultBuilder = new SarifResultBuilder();
            const sarifResultInit = {
                ruleId: ruleId,
                level: level,
                messageText: msg,
                fileUri: relative(rootdir, 'package.json'),

                startLine: 0,
                startColumn: 0,
                endLine: 0,
                endColumn: 0,
            };

            sarifResultInit.startLine = 1;
            sarifResultInit.startColumn = 1;
            sarifResultInit.endLine = 1;
            sarifResultInit.endColumn = 1;

            sarifResultBuilder.initSimple(sarifResultInit);
            sarifRunBuilder.addResult(sarifResultBuilder);
        }
    }

    sarifBuilder.addRun(sarifRunBuilder);

    const json = sarifBuilder.buildSarifJsonString({ indent: true });

    if (outputfilename) {
        writeFileSync(outputfilename, json);
    } else {
        console.log(json);
    }
}
