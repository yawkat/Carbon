package net.o2gaming.carbon.protocolmodifier;

import java.lang.reflect.InvocationTargetException;

import net.o2gaming.carbon.Carbon;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketContainer;
import com.comphenix.protocol.events.PacketEvent;

public class ProtocolBlockListener {

	private Carbon plugin;

	public ProtocolBlockListener(Carbon plugin) {
		this.plugin = plugin;
	}

	private int[] replacements = new int[4096];
	{
		for (int i = 0; i < replacements.length; i++) {
			replacements[i] = -1;
		}
		//slime -> emerald block
		replacements[165] = 133;
		//barrier -> ? (probably not needed) (or maybe glass?)

		// iron trapdoor -> trapdoor
		replacements[167] = 96;
		//prismarine -> mossy cobblestone
		replacements[168] = 48;
		//sea lantern -> glowstone
		replacements[169] = 89;
		//red sandstone -> sandstone
		replacements[179] = 24;
		//red sandstone stairs -> sandstone stairs
		replacements[180] = 128;
		//red sandstone doubleslab -> double step
		replacements[181] = 43;
		//red sandstone slab -> step
		replacements[182] = 44;
		//all fence gates -> fence gate
		replacements[183] = 107;
		replacements[184] = 107;
		replacements[185] = 107;
		replacements[186] = 107;
		replacements[187] = 107;
		//all fences -> fence
		replacements[188] = 85;
		replacements[189] = 85;
		replacements[190] = 85;
		replacements[191] = 85;
		replacements[192] = 85;
		//add doors -> door
		replacements[193] = 64;
		replacements[194] = 64;
		replacements[195] = 64;
		replacements[196] = 64;
		replacements[197] = 64;
		//TODO
	}

	public void init() {
		ProtocolLibrary.getProtocolManager().addPacketListener(
			new PacketAdapter(
				PacketAdapter.params(plugin, PacketType.Play.Server.MAP_CHUNK)
			) {
				@Override
				public void onPacketSending(PacketEvent event) {
					if (ProtocolLibrary.getProtocolManager().getProtocolVersion(event.getPlayer()) == 47) {
						return;
					}
					//chunk packet is split to 16 columns 16*16*16, if column doesn't have any blocks - it is not sent
					int blocksNumber = 4096 * getChunkSectionNumber(event.getPacket().getIntegers().read(2));
					byte[] data = event.getPacket().getByteArrays().read(1);
					for (int i = 0; i < blocksNumber; i++) {
						int id = data[i] & 0xFF;
						if (replacements[id] != -1) {
							data[i] = (byte) replacements[id];
						}
					}
				}
			}
		);

		ProtocolLibrary.getProtocolManager().addPacketListener(
			new PacketAdapter(
				PacketAdapter.params(plugin, PacketType.Play.Server.MAP_CHUNK_BULK)
			) {
				@Override
				public void onPacketSending(PacketEvent event) {
					if (ProtocolLibrary.getProtocolManager().getProtocolVersion(event.getPlayer()) == 47) {
						return;
					}
					//the same as map chunk, but we have multiple chunks data store in inflatedbuffers
					byte[][] inflatedBuffers = event.getPacket().getSpecificModifier(byte[][].class).read(0);
					int[] chunkSectionsData = event.getPacket().getIntegerArrays().read(2);
					for (int chunkNumber = 0; chunkNumber < inflatedBuffers.length; chunkNumber++) {
						int blocksNumber = 4096 * getChunkSectionNumber(chunkSectionsData[chunkNumber]);
						byte[] data =  inflatedBuffers[chunkNumber];
						for (int i = 0; i < blocksNumber; i++) {
							int id = data[i] & 0xFF;
							if (replacements[id] != -1) {
								data[i] = (byte) replacements[id];
							}
						}
					}
				}
			}
		);

		ProtocolLibrary.getProtocolManager().addPacketListener(
			new PacketAdapter(
				PacketAdapter.params(plugin, PacketType.Play.Server.BLOCK_CHANGE)
			) {
				@Override
				public void onPacketSending(PacketEvent event) {
					if (ProtocolLibrary.getProtocolManager().getProtocolVersion(event.getPlayer()) == 47) {
						return;
					}
					//create a new packet with modified block and send it (Had to do it because block change packets are shared)
					net.minecraft.server.v1_7_R4.Block block = event.getPacket().getSpecificModifier(net.minecraft.server.v1_7_R4.Block.class).read(0);
					int id = net.minecraft.server.v1_7_R4.Block.getId(block);
					if (replacements[id] != -1) {
						event.setCancelled(true);
						PacketContainer newpacket = new PacketContainer(PacketType.Play.Server.BLOCK_CHANGE);
						net.minecraft.server.v1_7_R4.Block newBlock = net.minecraft.server.v1_7_R4.Block.getById(replacements[id]);
						newpacket.getSpecificModifier(net.minecraft.server.v1_7_R4.Block.class).write(0, newBlock);
						newpacket.getIntegers().write(0, event.getPacket().getIntegers().read(0));
						newpacket.getIntegers().write(1, event.getPacket().getIntegers().read(1));
						newpacket.getIntegers().write(2, event.getPacket().getIntegers().read(2));
						newpacket.getIntegers().write(3, event.getPacket().getIntegers().read(3));
						try {
							ProtocolLibrary.getProtocolManager().sendServerPacket(event.getPlayer(), newpacket, false);
						} catch (InvocationTargetException e) {
						}
					}
				}
			}
		);

		ProtocolLibrary.getProtocolManager().addPacketListener(
			new PacketAdapter(
				PacketAdapter.params(plugin, PacketType.Play.Server.MULTI_BLOCK_CHANGE)
			) {
				@Override
				public void onPacketSending(PacketEvent event) {
					if (ProtocolLibrary.getProtocolManager().getProtocolVersion(event.getPlayer()) == 47) {
						return;
					}
					//the format is: 4 bytes (1st byte - ZX (or XZ, i don't remember and that doesn't matter here), 2nd byte - Y, 3,4th bytes - id 12 bits + data 4 bits)
					byte[] bytes = event.getPacket().getByteArrays().read(0);
					for (int i = 2; i < bytes.length; i+= 4) {
						int iddata = ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);
						int id = iddata >> 4;
						int data = iddata & 0xF;
						if (replacements[id] != -1) {
							int newiddata = replacements[id] << 4 | data;
							bytes[i] = (byte) (newiddata >> 8);
							bytes[i + 1] = (byte) newiddata;
						}
					}
				}
			}
		);
	}

	private int getChunkSectionNumber(int bitfield) {
		int count = 0;
		for (int i = 0; i < 16; i++) {
			if ((bitfield & (1 << i)) != 0) {
				count++;
			}
		}
		return count;
	}

}