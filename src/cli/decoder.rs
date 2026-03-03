use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Decoder management")]
pub struct DecoderCommand {
    #[command(subcommand)]
    pub action: DecoderAction,
}

#[derive(Subcommand)]
pub enum DecoderAction {
    /// List decoders
    List {
        /// Maximum number of items to return
        #[arg(long)]
        limit: Option<u32>,
    },

    /// List decoder files
    Files,

    /// Get a decoder file
    File {
        /// Decoder file name
        filename: String,
    },

    /// Update a decoder file
    Update {
        /// Decoder file name
        filename: String,

        /// Path to the local file
        #[arg(long)]
        file: String,
    },

    /// Delete a decoder file
    Delete {
        /// Decoder file name
        filename: String,
    },

    /// List parent decoders
    Parents,
}
