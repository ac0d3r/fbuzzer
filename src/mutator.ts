export class Mutator {
    static bitFlip(input: Uint8Array): Uint8Array {
        const out = input.slice();
        if (out.length === 0) return out;
        const idx = Math.floor(Math.random() * out.length);
        const bit = 1 << (Math.floor(Math.random() * 8));
        out[idx] ^= bit;
        return out;
    }

    static byteSet(input: Uint8Array): Uint8Array {
        const out = input.slice();
        if (out.length === 0) return out;
        const idx = Math.floor(Math.random() * out.length);
        out[idx] = Math.floor(Math.random() * 256);
        return out;
    }

    static byteInsert(input: Uint8Array): Uint8Array {
        const out = new Uint8Array(input.length + 1);
        const idx = Math.floor(Math.random() * (input.length + 1));
        out.set(input.slice(0, idx), 0);
        out[idx] = Math.floor(Math.random() * 256);
        out.set(input.slice(idx), idx + 1);
        return out;
    }

    static byteDelete(input: Uint8Array): Uint8Array {
        if (input.length === 0) return input;
        const idx = Math.floor(Math.random() * input.length);
        const out = new Uint8Array(input.length - 1);
        out.set(input.slice(0, idx), 0);
        out.set(input.slice(idx + 1), idx);
        return out;
    }

    static mutate(input: Uint8Array): Uint8Array {
        const strategies = [
            this.bitFlip,
            this.byteSet,
            this.byteInsert,
            this.byteDelete
        ];
        const strategy = strategies[Math.floor(Math.random() * strategies.length)];
        return strategy(input);
    }
}

export class CorpusManager {
    private corpus: Uint8Array[] = [];

    constructor(initialInputs?: Uint8Array[]) {
        if (initialInputs && initialInputs.length > 0) {
            this.corpus = initialInputs.slice();
        }
    }

    add(input: Uint8Array) {
        if (!this.contains(input)) {
            this.corpus.push(input);
        }
    }

    pick(): Uint8Array {
        const idx = Math.floor(Math.random() * this.corpus.length);
        return this.corpus[idx];
    }

    contains(input: Uint8Array): boolean {
        return this.corpus.some(item => CorpusManager.equals(item, input));
    }

    getAll(): Uint8Array[] {
        return this.corpus.slice();
    }

    size(): number {
        return this.corpus.length;
    }

    static equals(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }
}
