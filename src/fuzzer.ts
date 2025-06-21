import { Mutator, CorpusManager } from "./mutator";

export class CoverageCollector {
    public DEBUG: boolean = false;

    private events: any[] = [];
    private gcConter: number = 0;
    private funcAddr: NativePointer;

    public lastNewBlocks: number = 0;
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
                        console.log(`[*] New block found: ${addr}`);
                        self.globalCoverage.add(addr);
                        newBlocks++;
                    }
                }
                self.debug(`[+] New blocks in this run: ${newBlocks}, Total unique blocks: ${self.globalCoverage.size}`);
                self.lastNewBlocks = newBlocks;

                self.events = [];
            }
        });

    }

    getCoverage(): Set<string> {
        return this.globalCoverage;
    }

    resetCoverage() {
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

    constructor(targetFuncAddr: NativePointer, maxIters = 1000, initialInputs?: Uint8Array[]) {
        this.corpus = new CorpusManager(initialInputs);
        this.coverage = new CoverageCollector(targetFuncAddr, false);
        this.maxIters = maxIters;
        this.coverage.start();
    }

    run() {
        for (let i = 0; i < this.maxIters; i++) {
            const input = Mutator.mutate(this.corpus.pick());

            try {
                this.fuzz(input);
            } catch (e) {
                console.log(`[!] Crash detected at iteration ${i}, input: ${Array.from(input)}`);
                continue;
            }

            if (this.coverage.lastNewBlocks > 0) {
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

    fuzz(input: Uint8Array) {
        // TODO 具体调用函数放在这里去实现
    }

}
