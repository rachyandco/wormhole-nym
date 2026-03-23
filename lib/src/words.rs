use rand::seq::SliceRandom;

/// 512-word list for generating memorable wormhole codes.
/// Chosen for clarity (unambiguous pronunciation, 4-6 letters).
/// 512^3 ≈ 134 million combinations for a 3-word password.
pub const WORDS: &[&str] = &[
    "able", "acid", "aged", "arch", "area", "army", "away", "back", "ball", "band", "bank", "base",
    "bath", "bear", "bell", "belt", "bird", "bite", "blue", "boat", "bold", "bolt", "bone", "book",
    "boot", "burn", "buzz", "call", "calm", "card", "care", "case", "cash", "cave", "chip", "city",
    "clay", "clip", "club", "clue", "coal", "coat", "code", "coil", "cold", "come", "cone", "cool",
    "cope", "cord", "core", "corn", "cost", "crew", "crop", "cube", "cure", "dark", "data", "date",
    "dawn", "dead", "deal", "dear", "debt", "deck", "deep", "deer", "desk", "dice", "dirt", "disk",
    "dock", "dome", "done", "door", "dose", "down", "draw", "drop", "drug", "drum", "dual", "dull",
    "dump", "dusk", "dust", "duty", "earl", "earn", "east", "echo", "edge", "edit", "epic", "even",
    "evil", "exit", "face", "fact", "fair", "fall", "fame", "farm", "fast", "fate", "feed", "feel",
    "feet", "file", "fill", "film", "find", "fine", "fire", "firm", "fish", "flag", "flat", "flex",
    "flip", "flow", "foam", "fold", "fond", "food", "foot", "form", "fort", "free", "fuel", "full",
    "fund", "fury", "fuse", "gale", "game", "gang", "gate", "gave", "gaze", "gear", "gift", "girl",
    "give", "glad", "glow", "glue", "goal", "gold", "golf", "gone", "good", "gown", "grab", "gray",
    "grid", "grin", "grip", "grow", "gulf", "gust", "hack", "hail", "half", "hall", "halt", "hand",
    "hang", "hard", "harm", "have", "hawk", "haze", "head", "heal", "heap", "heat", "heel", "held",
    "helm", "help", "here", "hero", "hike", "hill", "hint", "hire", "hole", "iron", "jack", "jail",
    "jazz", "join", "jump", "jury", "keen", "keep", "kill", "kind", "king", "kiss", "knee", "knew",
    "know", "lack", "lake", "land", "lane", "last", "late", "lazy", "lead", "leaf", "lean", "left",
    "lend", "lens", "life", "lift", "like", "lime", "link", "list", "live", "load", "lock", "lone",
    "long", "look", "lore", "lost", "love", "luck", "lung", "mail", "main", "many", "mark", "math",
    "maze", "meal", "meat", "melt", "mild", "mill", "mind", "mine", "mint", "miss", "mode", "moon",
    "more", "move", "much", "mule", "near", "neck", "need", "news", "nice", "none", "noon", "norm",
    "note", "open", "oral", "oven", "over", "pain", "pair", "palm", "park", "part", "past", "path",
    "peak", "peel", "peer", "pill", "pine", "pink", "pipe", "plan", "play", "plot", "plow", "plug",
    "plus", "poem", "port", "pose", "pour", "pray", "pure", "push", "race", "rage", "raid", "rail",
    "rain", "rank", "rare", "rate", "read", "real", "reed", "rely", "rent", "rest", "rice", "rich",
    "ride", "ring", "rise", "risk", "road", "roam", "roar", "rock", "role", "roll", "roof", "rope",
    "rose", "rude", "ruin", "rule", "rush", "safe", "sage", "sail", "salt", "same", "sand", "save",
    "seal", "seed", "self", "sell", "shed", "ship", "shoe", "shop", "shot", "show", "sick", "sigh",
    "sign", "silk", "sing", "sink", "size", "skin", "skip", "slam", "slim", "slip", "slow", "snow",
    "sock", "soft", "soil", "some", "song", "soon", "sort", "soul", "soup", "sour", "span", "spin",
    "spot", "star", "stay", "stem", "step", "stir", "stop", "such", "suit", "sung", "sure", "swim",
    "tail", "tale", "talk", "tall", "tank", "tape", "task", "teen", "tell", "tend", "tent", "term",
    "than", "then", "thin", "tied", "tile", "time", "tire", "told", "toll", "tone", "took", "town",
    "trap", "tree", "trim", "true", "tube", "tune", "turf", "turn", "twin", "type", "ugly", "unit",
    "upon", "urge", "used", "vain", "vast", "view", "vote", "wade", "wage", "wake", "walk", "ward",
    "warm", "warn", "warp", "wash", "wave", "wear", "weld", "went", "west", "wide", "wife", "wild",
    "will", "wind", "wine", "wing", "wire", "wise", "wish", "wolf", "wood", "word", "wore", "work",
    "worm", "worn", "wrap", "yard", "year", "zero", "zone",
];

pub fn generate_password(num_words: usize) -> String {
    let mut rng = rand::thread_rng();
    WORDS
        .choose_multiple(&mut rng, num_words)
        .copied()
        .collect::<Vec<_>>()
        .join("-")
}
