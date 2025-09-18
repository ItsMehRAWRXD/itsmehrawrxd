// Add this to ComprehensiveRootingApp.java 
 
// Load simple native library 
static { 
    try { 
        System.loadLibrary("simple_root_engine"); 
    } catch (UnsatisfiedLinkError e) { 
        Log.e(TAG, "Failed to load simple native library", e); 
    } 
} 
 
// Native method declarations 
private native boolean trySimpleNativeRoot(); 
