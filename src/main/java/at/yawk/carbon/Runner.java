package at.yawk.carbon;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.*;
import java.util.Arrays;
import java.util.jar.Manifest;
import sun.misc.Resource;
import sun.misc.URLClassPath;

/**
 * @author yawkat
 */
public class Runner {
    public static void main(String[] args) throws MalformedURLException, ReflectiveOperationException {
        File jarFile = new File(args[0]);
        String[] bukkitArgs = Arrays.copyOfRange(args, 1, args.length);

        System.out.println("Launching carbon on " + jarFile + " args " + Arrays.toString(bukkitArgs));

        ClassLoader classLoader = new MainClassLoader(
                Runner.class.getProtectionDomain().getCodeSource().getLocation(),
                jarFile.toURI().toURL()
        );

        Thread.currentThread().setContextClassLoader(classLoader);

        Class<?> mainClass = classLoader.loadClass("org.bukkit.craftbukkit.Main");
        Method main = mainClass.getMethod("main", String[].class);

        main.invoke(null, (Object) bukkitArgs);
    }

    private static class MainClassLoader extends URLClassLoader {
        private final URLClassPath ucp;
        private final AccessControlContext acc;

        public MainClassLoader(URL... urls) throws ReflectiveOperationException {
            super(urls);

            Field ucpField = URLClassLoader.class.getDeclaredField("ucp");
            ucpField.setAccessible(true);
            ucp = (URLClassPath) ucpField.get(this);

            Field accField = URLClassLoader.class.getDeclaredField("acc");
            accField.setAccessible(true);
            acc = (AccessControlContext) accField.get(this);
        }

        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            // do not load carbon classes so we can still load the plugin from a plugin-specific class loader
            if (name.startsWith("com.lastabyss.carbon")) { throw new ClassNotFoundException(name); }

            synchronized (getClassLoadingLock(name)) {
                // First, check if the class has already been loaded
                Class<?> c = findLoadedClass(name);
                if (c == null) {
                    long t0 = System.nanoTime();
                    try {
                        // If still not found, then invoke findClass in order
                        // to find the class.
                        long t1 = System.nanoTime();
                        c = findClass(name);

                        // this is the defining class loader; record the stats
                        sun.misc.PerfCounter.getParentDelegationTime().addTime(t1 - t0);
                        sun.misc.PerfCounter.getFindClassTime().addElapsedTimeFrom(t1);
                        sun.misc.PerfCounter.getFindClasses().increment();
                    } catch (ClassNotFoundException e) {
                        // ClassNotFoundException thrown if class not found
                        // from the non-null parent class loader
                    }

                    if (c == null) {
                        return super.loadClass(name, resolve);
                    }
                }
                if (resolve) {
                    resolveClass(c);
                }
                return c;
            }
        }

        private Class<?> defineClass(String name, Resource res) throws IOException {
            long t0 = System.nanoTime();
            int i = name.lastIndexOf('.');
            URL url = res.getCodeSourceURL();
            if (i != -1) {
                String pkgname = name.substring(0, i);
                // Check if package already loaded.
                Manifest man = res.getManifest();
                if (getPackage(pkgname) == null) {
                    try {
                        if (man != null) {
                            definePackage(pkgname, man, url);
                        } else {
                            definePackage(pkgname, null, null, null, null, null, null, null);
                        }
                    } catch (IllegalArgumentException iae) {
                        // parallel-capable class loaders: re-verify in case of a
                        // race condition
                        if (getPackage(pkgname) == null) {
                            // Should never happen
                            throw new AssertionError("Cannot find package " +
                                                     pkgname);
                        }
                    }
                }
            }
            // Now read the class bytes and define the class
            java.nio.ByteBuffer bb = res.getByteBuffer();
            if (bb != null) {
                // Use (direct) ByteBuffer:
                CodeSigner[] signers = res.getCodeSigners();
                CodeSource cs = new CodeSource(url, signers);
                sun.misc.PerfCounter.getReadClassBytesTime().addElapsedTimeFrom(t0);
                return defineClass(name, bb, cs);
            } else {
                byte[] b = res.getBytes();
                // must read certificates AFTER reading bytes.
                CodeSigner[] signers = res.getCodeSigners();
                CodeSource cs = new CodeSource(url, signers);
                sun.misc.PerfCounter.getReadClassBytesTime().addElapsedTimeFrom(t0);
                return defineClass(name, b, 0, b.length, cs);
            }
        }

        @Override
        protected Class<?> findClass(final String name)
                throws ClassNotFoundException {
            try {
                return AccessController.doPrivileged(
                        new PrivilegedExceptionAction<Class<?>>() {
                            public Class<?> run() throws ClassNotFoundException {
                                String path = name.replace('.', '/').concat(".class");
                                Resource res = ucp.getResource(path, false);
                                if (res != null) {
                                    try {
                                        return defineClass(name, res);
                                    } catch (IOException e) {
                                        throw new ClassNotFoundException(name, e);
                                    }
                                } else {
                                    throw new ClassNotFoundException(name);
                                }
                            }
                        }, acc);
            } catch (java.security.PrivilegedActionException pae) {
                throw (ClassNotFoundException) pae.getException();
            }
        }
    }
}
