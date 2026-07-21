import mongoose from 'mongoose';

const MONGO_URI = 'mongodb+srv://abdullah1:Abdullah100mph@cluster0.1tkn159.mongodb.net/syncboard?retryWrites=true&w=majority&appName=Cluster0';

async function hardWipeDB() {
  try {
    console.log("⏳ Connecting to MongoDB...");
    await mongoose.connect(MONGO_URI);
    
    const collections = await mongoose.connection.db.listCollections().toArray();

    for (const col of collections) {
      const colName = col.name;

      // Keep your Pro PIN collection safe
      if (colName.toLowerCase().includes('pin') || colName.toLowerCase().includes('pro')) {
        console.log(`🛡️ Preserving Pro Records: ${colName}`);
        continue;
      }

      // DROP the collection completely instead of just deleting documents
      await mongoose.connection.db.dropCollection(colName);
      console.log(`💥 Dropped collection: ${colName}`);
    }

    console.log("\n✅ Database completely cleared!");
  } catch (error) {
    console.error("❌ Wipe failed:", error);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

hardWipeDB();