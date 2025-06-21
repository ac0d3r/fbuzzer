import { Fuzzer } from '../fuzzer.js';

export class Example1 extends Fuzzer {
    public nativeFunc;

    constructor() {
        const addr: NativePointer = Module.getGlobalExportByName("bb");
        if (!addr) throw new Error(`function not found`);

        super(addr);
        this.nativeFunc = new NativeFunction(addr, 'int', ['int8']);
    }

    fuzz(input: Uint8Array): void {
        const arg = input[0] % 256; // 假设输入是一个字节，转换为 int8
        console.log(`Calling native function with arg: ${arg}`);
        this.nativeFunc(arg);
    }
}


setImmediate(() => {
    const fuzzer = new Example1();
    fuzzer.run();
});