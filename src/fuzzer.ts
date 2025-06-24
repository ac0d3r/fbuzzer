import { Mutator, CorpusManager } from "./mutator.js";

export class CoverageCollector {
    public DEBUG: boolean = false;

    private events: any[] = [];
    private gcConter: number = 0;
    private funcAddr: NativePointer;

    private _lastNewBlocks: number = 0;
    private globalCoverage: Set<string> = new Set();


    constructor(funcAddr: NativePointer, debug: boolean = false) {
        this.DEBUG = debug;

        this.funcAddr = funcAddr;
        Stalker.trustThreshold = 3;
        Stalker.queueCapacity = 0x8000;
        Stalker.queueDrainInterval = 1000 * 1000;
    }

    start() {
        const self = this;

        Interceptor.attach(this.funcAddr, {
            onEnter: function (args) {
                self.debug(`[*] Interceptor ENTER (${Date.now()})`);
                self.events = [];

                Stalker.follow(Process.getCurrentThreadId(), {
                    events: {
                        call: false,
                        ret: false,
                        exec: false,
                        block: false,
                        compile: true
                    },
                    onReceive: (events) => {
                        const parsed = Stalker.parse(events, { stringify: false, annotate: false });
                        self.events.push(...parsed);
                    }
                });
            },
            onLeave: function () {
                self.debug(`[*] Interceptor LEAVE (${Date.now()})`);

                Stalker.unfollow();
                Stalker.flush();
                if (self.gcConter > 300) {
                    Stalker.garbageCollect();
                    self.gcConter = 0;
                }
                self.gcConter++;

                let newBlocks = 0;
                for (const event of self.events) {
                    const addr = event[1]?.toString?.() ?? String(event[1]);
                    if (!self.globalCoverage.has(addr)) {
                        self.globalCoverage.add(addr);
                        newBlocks++;
                    }
                }

                self.debug(`[+] New blocks in this run: ${newBlocks}, Total unique blocks: ${self.globalCoverage.size}`);
                self._lastNewBlocks = newBlocks;

                self.events = [];
            }
        });

    }

    lastNewBlocks(): boolean {
        const hasNew = this._lastNewBlocks > 0;
        this._lastNewBlocks = 0;
        return hasNew;
    }

    getCoverage(): Set<string> {
        return this.globalCoverage;
    }

    reset() {
        this.globalCoverage.clear();
    }

    debug(msg: string) {
        if (this.DEBUG) { console.log("[+ (" + Process.id + ")] " + msg); }
    }
}


export class Fuzzer {
    private corpus: CorpusManager;
    private coverage: CoverageCollector;
    private maxIters: number;
    private minLength: number;
    private maxLength: number;

    constructor(targetFuncAddr: NativePointer, options: {
        maxIters?: number,
        minLength?: number,
        maxLength?: number,
        initialInputs?: Uint8Array[]
    } = {}) {
        const {
            maxIters = 1000,
            minLength = 1,  // TODO
            maxLength = -1, // -1 means no limit
            initialInputs = undefined
        } = options;

        this.maxIters = maxIters;
        this.minLength = minLength;
        this.maxLength = maxLength;

        if (!initialInputs || initialInputs.length === 0) {
            const defaultInput = new Uint8Array(this.minLength).fill(0);
            this.corpus = new CorpusManager([defaultInput]);
        } else {
            const validInitialInputs = initialInputs.filter(
                input => input.length >= this.minLength && (this.maxLength === -1 || input.length <= this.maxLength)
            );

            if (validInitialInputs.length === 0) {
                const defaultInput = new Uint8Array(this.minLength).fill(0);
                this.corpus = new CorpusManager([defaultInput]);
            } else {
                this.corpus = new CorpusManager(validInitialInputs);
            }
        }


        this.coverage = new CoverageCollector(targetFuncAddr, false);
        this.coverage.start();
    }

    run() {
        for (let i = 0; i < this.maxIters; i++) {
            const input = this.mutateWithConstraints(this.corpus.pick());

            try {
                this.fuzz(input);
            } catch (e) {
                console.log(`[!] Crash detected at iteration ${i}, input: ${Array.from(input)}`);
                continue;
            }

            if (this.coverage.lastNewBlocks()) {
                this.corpus.add(input);
                console.log(`[+] New path found! Corpus size: ${this.corpus.size()}`);
            }

            if (i % 100 === 0) {
                console.log(`[.] Iteration ${i}, corpus size: ${this.corpus.size()}, coverage: ${this.coverage.getCoverage().size}`);
            }
        }
        console.log(`[+] Fuzzing done. Total corpus: ${this.corpus.size()}, coverage: ${this.coverage.getCoverage().size}`);

        console.log('[*] Corpus content:');
        this.corpus.getAll().forEach((item, idx) => {
            console.log(`[${idx}]:`, Array.from(item));
        });
    }

    private mutateWithConstraints(input: Uint8Array): Uint8Array {
        let mutated = Mutator.mutate(input);
        if (this.maxLength == -1) { return mutated; } // 不限制长度

        if (mutated.length < this.minLength) {
            const newInput = new Uint8Array(this.minLength);
            newInput.set(mutated);
            for (let i = mutated.length; i < this.minLength; i++) {
                newInput[i] = Math.floor(Math.random() * 256);
            }
            mutated = newInput;
        } else if (mutated.length > this.maxLength) {
            mutated = mutated.slice(0, this.maxLength);
        }

        return mutated;
    }

    fuzz(input: Uint8Array) {
        // TODO 具体调用函数放在这里去实现
    }

}
