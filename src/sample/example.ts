import { Fuzzer } from '../fuzzer.js';

export class Example1 extends Fuzzer {
    public nativeFunc;

    constructor() {
        const addr: NativePointer = Module.getGlobalExportByName("bb");
        if (!addr) throw new Error(`function not found`);

        super(addr, {
            maxIters: 1000,
            maxLength: 1,
        });
        this.nativeFunc = new NativeFunction(addr, 'int', ['int8']);
    }

    fuzz(input: Uint8Array): void {
        const arg = input[0];
        console.log(`Calling native function with arg: ${arg}`);
        this.nativeFunc(arg);
    }
}


setImmediate(() => {
    const fuzzer = new Example1();
    fuzzer.run();
});