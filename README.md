# Fbuzzer

<span>
<img src="./docs/fbuzzer.png" alt="fbuzzer" width="50" style="vertical-align:middle; margin-right:10px;"/>
Fbuzzer is a toy coverage-guided fuzzer based on Frida. It supports custom mutation, coverage collection, and crash detection. Suitable for prototyping and learning fuzzing principles.
</span>

## Features

- Dynamic instrumentation and coverage collection via Frida
- Toy mutator (bit flip, byte set, etc.)
- Automatic corpus management: new paths are added automatically
- Pure TypeScript/JavaScript implementation, easy to extend

## Usage

1. **Build the Agent**

```sh
npm run build
# or
frida-compile -S -c src/sample/example.ts -o _agent.js
```

2. **Attach the Fuzzer Agent**
   
```sh
frida -l _agent.js -n example
```
