// Simple Dependency Injector for RawrZ platform
// Provides a tiny service container with singleton and factory bindings

class Injector {
    constructor(parent = null) {
        this.parent = parent;
        this.bindings = new Map(); // name -> { type: 'value'|'factory'|'singleton', provider, instance }
    }

    registerValue(name, value) {
        if (!name) throw new Error('Injector.registerValue requires a name');
        this.bindings.set(name, { type: 'value', provider: () => value, instance: value });
        return this;
    }

    registerFactory(name, factory) {
        if (!name) throw new Error('Injector.registerFactory requires a name');
        if (typeof factory !== 'function') throw new Error('Factory must be a function');
        this.bindings.set(name, { type: 'factory', provider: factory, instance: null });
        return this;
    }

    registerSingleton(name, factoryOrValue) {
        if (!name) throw new Error('Injector.registerSingleton requires a name');
        const isFunction = typeof factoryOrValue === 'function';
        const provider = isFunction ? factoryOrValue : () => factoryOrValue;
        this.bindings.set(name, { type: 'singleton', provider, instance: null });
        return this;
    }

    has(name) {
        return this.bindings.has(name) || (this.parent ? this.parent.has(name) : false);
    }

    resolve(name) {
        if (this.bindings.has(name)) {
            const binding = this.bindings.get(name);
            if (binding.type === 'value') {
                return binding.instance;
            }
            if (binding.type === 'singleton') {
                if (binding.instance === null) {
                    binding.instance = binding.provider(this);
                }
                return binding.instance;
            }
            // factory
            return binding.provider(this);
        }
        if (this.parent) {
            return this.parent.resolve(name);
        }
        throw new Error(`Injector: Service not found: ${name}`);
    }

    createChild() {
        return new Injector(this);
    }

    clear() {
        this.bindings.clear();
    }
}

// Global singleton injector
const injector = new Injector();

module.exports = {
    Injector,
    injector
};

