package masksite

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Article represents a blog post on the camouflage site.
type Article struct {
	ID             string
	Title          string
	Date           string
	ReadTime       string
	Category       string
	Tags           []string
	Excerpt        string
	BodyParagraphs []string
	KeyTakeaway    string
}

// SiteMeta holds descriptive info about the generated camouflage site.
type SiteMeta struct {
	BlogTitle      string    `json:"blogTitle"`
	Tagline        string    `json:"tagline"`
	AuthorName     string    `json:"authorName"`
	AuthorRole     string    `json:"authorRole"`
	AuthorLocation string    `json:"authorLocation"`
	AuthorBio      string    `json:"authorBio"`
	Category       string    `json:"category"`
	AccentColor    string    `json:"accentColor"`
	SecondaryColor string    `json:"secondaryColor"`
	AccentGlow     string    `json:"accentGlow"`
	BgColor        string    `json:"bgColor"`
	SurfaceColor   string    `json:"surfaceColor"`
	SurfaceHover   string    `json:"surfaceHover"`
	BorderColor    string    `json:"borderColor"`
	TextMain       string    `json:"textMain"`
	TextMuted      string    `json:"textMuted"`
	ArticleCount   int       `json:"articleCount"`
	Articles       []Article `json:"articles,omitempty"`
	GeneratedAt    string    `json:"generatedAt"`
}

type themePreset struct {
	Category        string
	BlogTitles      []string
	Taglines        []string
	Authors         []string
	Roles           []string
	Locations       []string
	Bios            []string
	ColorAccents    []colorPair
	Articles        []Article
}

type colorPair struct {
	Accent    string
	Secondary string
	Glow      string
}

func secureRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return int(time.Now().UnixNano() % int64(max))
	}
	return int(nBig.Int64())
}

func getThemes() []themePreset {
	return []themePreset{
		// 1. Systems & Low-Level Infrastructure
		{
			Category: "Systems & Distributed Engineering",
			BlogTitles: []string{
				"Substrate Journal",
				"Latency & Wire",
				"Kernel Craft",
				"Low-Level Dispatch",
				"The Wireframe Log",
				"Systems & Protocols",
			},
			Taglines: []string{
				"Technical reflections on Linux kernel networking, memory models, and zero-allocation systems.",
				"Notes on high-throughput distributed consensus, hardware topologies, and network protocols.",
				"Dispatches from bare-metal optimization, modern Linux internals, and async runtimes.",
			},
			Authors: []string{
				"Julian Mercer",
				"Liam Vance",
				"Marcus Thorne",
				"Adrian Sterling",
				"Tobias Lindholm",
			},
			Roles: []string{
				"Principal Systems Architect & Linux Kernel Contributor",
				"Distributed Infrastructure Engineer & Protocol Researcher",
				"Low-Latency Platform Engineer",
				"Site Reliability & Runtime Systems Specialist",
			},
			Locations: []string{
				"Zurich, Switzerland",
				"Seattle, WA",
				"Stockholm, Sweden",
				"Oslo, Norway",
				"Vancouver, BC",
			},
			Bios: []string{
				"Obsessed with cache line alignment, eBPF tracing, and eliminating unpredictable jitter across thousands of distributed nodes.",
				"Building predictable, resilient distributed storage engines while tracking Linux kernel TCP subsystem evolutions.",
				"Focusing on hardware-software boundaries, NVMe throughput, and memory compaction across multicore architectures.",
			},
			ColorAccents: []colorPair{
				{Accent: "#38bdf8", Secondary: "#0284c7", Glow: "rgba(56, 189, 248, 0.14)"}, // Sky Cyan
				{Accent: "#60a5fa", Secondary: "#2563eb", Glow: "rgba(96, 165, 250, 0.14)"}, // Royal Blue
				{Accent: "#34d399", Secondary: "#059669", Glow: "rgba(52, 211, 153, 0.14)"}, // Mint Emerald
			},
			Articles: []Article{
				{
					ID:       "ebpf-packet-filtering",
					Title:    "Dissecting eBPF Packet Filtering at 100GbE Line Rate",
					Date:     "Jan 18, 2026",
					ReadTime: "7 min read",
					Category: "Networking",
					Tags:     []string{"eBPF", "XDP", "Linux", "Performance"},
					Excerpt:  "When handling tens of millions of packets per second, traditional socket buffers and context switches introduce unacceptable latency. Here is how XDP ringbuffers bypass OS overhead.",
					BodyParagraphs: []string{
						"Modern multi-hundred gigabit network interfaces demand architectural shifts in how the Linux kernel handles ingress frames. By offloading packet filtering directly into the eXpress Data Path (XDP) layer within the device driver, packets are evaluated before the allocation of SKB metadata structures.",
						"Through carefully bounded eBPF verification routines, we demonstrate an atomic BPF map lookup pattern that achieves sub-microsecond filtering decisions without incurring cache line contention across NUMA domains.",
						"Furthermore, utilizing AF_XDP zero-copy socket rings enables userspace packet processors to ingest raw ethernet frames directly, dropping kernel-to-userspace copies from three to zero on supported Mellanox ConnectX silicon.",
					},
					KeyTakeaway: "Offloading packet triage to XDP ringbuffers maintains deterministic sub-microsecond latency regardless of host connection pressure.",
				},
				{
					ID:       "eventual-consistency-consensus",
					Title:    "The Fallacy of Eventual Consistency in Multi-Region Consensus",
					Date:     "Dec 04, 2025",
					ReadTime: "9 min read",
					Category: "Architecture",
					Tags:     []string{"Raft", "Distributed Systems", "Consensus"},
					Excerpt:  "Eventual consistency sounds appealing until an unexpected network partition exposes stale read anomalies. A study of leader leases and WAN roundtrips.",
					BodyParagraphs: []string{
						"Cross-region replication strategies frequently compromise strict linearizability under the banner of high availability. However, when financial transaction records or distributed lock primitives depend on wall-clock synchronicity, subtle time skew can cascade into split-brain catastrophes.",
						"We examine leader lease renewals across Atlantic fiber spans. When roundtrip times fluctuate due to undersea cable rerouting, Raft heartbeat timeouts must dynamically adapt to prevent unwarranted election cycles.",
						"By pairing bounded monotonic clocks with logical sequence barriers, distributed state machines can achieve zero-wait local reads without sacrificing causal guarantees across heterogeneous cloud regions.",
					},
					KeyTakeaway: "Bounded monotonic clocks and adaptive leader leases reconcile low read latency with strict distributed linearizability.",
				},
				{
					ID:       "linux-memory-compaction",
					Title:    "Memory Compaction and HugePages in High-Throughput Daemons",
					Date:     "Oct 22, 2025",
					ReadTime: "6 min read",
					Category: "Internals",
					Tags:     []string{"Linux", "Memory", "HugePages", "Kernel"},
					Excerpt:  "Investigating how transparent huge pages (THP) and background compaction daemons introduce tail-latency spikes in long-running Go and C++ services.",
					BodyParagraphs: []string{
						"Transparent Huge Pages (THP) promise substantial TLB miss reductions for memory-intensive applications. Yet in production environments managing hundreds of gigabytes of working set memory, the kernel's kcompactd daemon can trigger synchronous compaction freezes lasting several hundred milliseconds.",
						"By instrumenting perf events and tracing mm_compaction_begin kernel probes, we uncover how aggressive defragmentation locks page blocks across populated zone lists.",
						"The optimal mitigation pairs madvise-based explicit 2MB page reservations with tuned vm.extfrag_threshold parameters, eliminating latency jitter while preserving the performance benefits of spacious TLB translation caches.",
					},
					KeyTakeaway: "Explicit madvise reservations prevent kcompactd stop-the-world defragmentation pauses in high-throughput services.",
				},
				{
					ID:       "zero-copy-serialization",
					Title:    "Zero-Copy Serialization: FlatBuffers vs Protobuf in Hot Paths",
					Date:     "Aug 15, 2025",
					ReadTime: "8 min read",
					Category: "Protocols",
					Tags:     []string{"Protobuf", "FlatBuffers", "IPC", "C++"},
					Excerpt:  "Comparing memory allocation profiles, traversal efficiency, and schema evolution flexibility when sending 1M IPC messages per second across memory-mapped buffers.",
					BodyParagraphs: []string{
						"Parsing traditional Protocol Buffers requires deserializing bytes into freshly allocated language objects. In high-frequency IPC scenarios, this continuous object churning induces noticeable garbage collection pause times and CPU cache thrashing.",
						"FlatBuffers take a fundamentally different approach: data is laid out in memory matching its wire representation, allowing field access directly through vtable offsets without unpacking.",
						"Our benchmarks highlight that while FlatBuffers require greater developer rigor in schema construction, they eliminate 98% of heap allocations on critical hot paths, sustaining deterministic throughput under peak workloads.",
					},
					KeyTakeaway: "FlatBuffers' direct-memory vtable access eliminates heap churn in ultra-low latency IPC pipelines.",
				},
			},
		},

		// 2. Modern Product Design & Typography
		{
			Category: "Minimalist Design & Typography",
			BlogTitles: []string{
				"Nordic Grid",
				"Quiet Artifacts",
				"Negative Space",
				"The Design Lens",
				"Form & Radius",
				"Typographic Cadence",
			},
			Taglines: []string{
				"A curated archive exploring optical typography, spatial balance, and calm digital interfaces.",
				"Notes on restrained aesthetics, micro-interactions, and design systems with longevity.",
				"Observations on visual hierarchy, tactile ergonomics, and digital craftsmanship.",
			},
			Authors: []string{
				"Maya Lindqvist",
				"Linnea Strand",
				"Soren Eklund",
				"Elena Rostova",
				"Astrid Vang",
			},
			Roles: []string{
				"Design Systems Director & Typographic Researcher",
				"Independent Product Designer & Minimalist Craftsman",
				"Principal UI/UX Architect",
				"Visual Ergonomist & Creative Technologist",
			},
			Locations: []string{
				"Stockholm, Sweden",
				"Copenhagen, Denmark",
				"Kyoto, Japan",
				"Helsinki, Finland",
				"Portland, OR",
			},
			Bios: []string{
				"Dedicated to the pursuit of quiet interfaces that respect human attention and resist ephemeral design trends.",
				"Crafting modular design languages grounded in Scandinavian functionalism and rigorous typographic discipline.",
				"Exploring the intersection of tactile physical materials and purposeful, high-contrast digital experiences.",
			},
			ColorAccents: []colorPair{
				{Accent: "#a78bfa", Secondary: "#7c3aed", Glow: "rgba(167, 139, 250, 0.14)"}, // Lavender Violet
				{Accent: "#fb7185", Secondary: "#e11d48", Glow: "rgba(251, 113, 133, 0.14)"}, // Rose Coral
				{Accent: "#e2e8f0", Secondary: "#94a3b8", Glow: "rgba(226, 232, 240, 0.12)"}, // Monochrome Slate
			},
			Articles: []Article{
				{
					ID:       "optical-weight-typography",
					Title:    "The Optical Weight of Sans-Serif Micro-Typography",
					Date:     "Jan 12, 2026",
					ReadTime: "6 min read",
					Category: "Typography",
					Tags:     []string{"Typography", "Design Systems", "Accessibility"},
					Excerpt:  "Designing legible sub-12px glyphs for dense technical dashboards requires deliberate compensations in counters, aperture openness, and letter tracking.",
					BodyParagraphs: []string{
						"When rendering text at diminutive scale on high-density displays, traditional typographic proportions collapse. Closed apertures clog with pixels, and thin crossbars vanish against dark themes.",
						"By introducing subtle ink traps, expanding x-height, and loosening horizontal tracking by 1.5-2%, we can restore instantaneous recognizability to telemetry counters and status badges.",
						"Great typography is not noticed; it effortlessly delivers meaning into the consciousness of the reader before cognitive friction can form.",
					},
					KeyTakeaway: "Generous apertures and calculated tracking adjustments ensure crystal-clear legibility at compact scale.",
				},
				{
					ID:       "spatial-rhythms-baseline",
					Title:    "Spatial Rhythms: Beyond the Strict 8-Point Baseline Grid",
					Date:     "Nov 28, 2025",
					ReadTime: "8 min read",
					Category: "Layout",
					Tags:     []string{"Grid Systems", "UI Design", "Visual Cadence"},
					Excerpt:  "While linear grids provide engineering convenience, natural visual harmony often demands non-linear spacing ratios that mirror musical cadences.",
					BodyParagraphs: []string{
						"The ubiquitous 8pt grid has streamlined digital handoffs, but dogmatic adherence often yields predictable, rigid compositions that feel mechanical rather than inviting.",
						"By borrowing spatial progressions from architectural proportions and classical page layout geometry, we introduce dynamic breathing room between competing informational clusters.",
						"Contextual density scaling allows complex analytical software to communicate profound clarity without sacrificing analytical density.",
					},
					KeyTakeaway: "Dynamic spatial cadences impart human warmth and intuitive hierarchy to structured layouts.",
				},
				{
					ID:       "designing-cognitive-calm",
					Title:    "Designing for Cognitive Calm in High-Density Interfaces",
					Date:     "Oct 09, 2025",
					ReadTime: "5 min read",
					Category: "Ergonomics",
					Tags:     []string{"Cognitive Load", "Minimalism", "UX"},
					Excerpt:  "How muted color palettes, intentional silence, and progressive disclosure protect user focus in an era of incessant notification fatigue.",
					BodyParagraphs: []string{
						"Every saturated color badge and animated transition competes aggressively for the user's finite neurological attention. When interfaces scream for attention, comprehension drops precipitously.",
						"We investigate a calming design philosophy: neutral monochrome backgrounds paired with single-point semantic accenting. Elements remain subdued until human intent calls them forward.",
						"A thoughtful interface acts as a silent tool: present when summoned, unobtrusive when delivering utility, and respectful of the human mind.",
					},
					KeyTakeaway: "Intentional visual restraint transforms intimidating software into a reliable instrument of calm focus.",
				},
				{
					ID:       "fluid-view-transitions",
					Title:    "Fluid Fluidity: View Transitions in Modern Web Architecture",
					Date:     "Aug 30, 2025",
					ReadTime: "7 min read",
					Category: "Engineering",
					Tags:     []string{"CSS", "Web Standards", "Interaction"},
					Excerpt:  "Implementing seamless spatial page transitions using native browser View Transitions API without heavyweight single-page app overhead.",
					BodyParagraphs: []string{
						"For years, creating cinematic state transitions between web views required heavy JavaScript routing frameworks that bloated page bundle sizes and delayed initial paint times.",
						"With the standardization of the CSS View Transitions API, native browsers can snapshot document states and smoothly interpolate layout boxes directly on the compositor thread.",
						"The result is tactile, app-like elegance paired with the lightweight resilience and blistering load speeds of pure semantic HTML.",
					},
					KeyTakeaway: "Native browser view transitions provide cinematic fluidity without the weight of client-side routing monoliths.",
				},
			},
		},

		// 3. Alpine Expeditions & Wilderness Notes
		{
			Category: "Alpine Exploration & Field Notes",
			BlogTitles: []string{
				"Ridge & Summit",
				"The Northern Route",
				"Alpinist Dispatches",
				"Contour & Elevation",
				"High Pass Journal",
				"Wilderness Logbook",
			},
			Taglines: []string{
				"Dispatches from solitary alpine ascents, glacial crossings, and sub-zero survival gear testing.",
				"Documenting high-altitude traverses, navigational discipline, and minimalist expedition equipment.",
				"Reflections from high ridge bivouacs, granite spires, and wilderness photography.",
			},
			Authors: []string{
				"Adrian Croft",
				"Ethan Gallagher",
				"Nolan Finch",
				"Henrik Lindqvist",
				"David Sterling",
			},
			Roles: []string{
				"Alpine Guide & Extreme Weather Equipment Tester",
				"Wilderness Cartographer & Solo Mountaineer",
				"Expedition Photographer & Survivalist",
				"Backcountry Navigator & Route Specialist",
			},
			Locations: []string{
				"Chamonix, France",
				"Innsbruck, Austria",
				"Banff, Canada",
				"Tromsø, Norway",
				"Boulder, Colorado",
			},
			Bios: []string{
				"Drawn to severe granite walls, frozen couloirs, and the stark mental clarity that only solitary exposure above 4,000 meters can grant.",
				"Testing modern ultralight alpine fabrics across remote glaciated ranges, balancing weight reduction against storm safety margins.",
				"Recording the seasonal shifts of northern glaciers and navigating uncharted backcountry passes with map, compass, and barometric altimeter.",
			},
			ColorAccents: []colorPair{
				{Accent: "#38bdf8", Secondary: "#0369a1", Glow: "rgba(56, 189, 248, 0.14)"}, // Glacial Blue
				{Accent: "#34d399", Secondary: "#059669", Glow: "rgba(52, 211, 153, 0.14)"}, // Alpine Moss
				{Accent: "#fbbf24", Secondary: "#b45309", Glow: "rgba(251, 191, 36, 0.14)"}, // High Amber
			},
			Articles: []Article{
				{
					ID:       "bernese-ridge-traverse",
					Title:    "Solitary Traverse of the Bernese High Ridges in Late Autumn",
					Date:     "Jan 06, 2026",
					ReadTime: "8 min read",
					Category: "Alpinism",
					Tags:     []string{"Alps", "Bivouac", "Mountaineering", "Winter"},
					Excerpt:  "Route-finding across knife-edge cornices as cold arctic fronts descend. Managing caloric deficits, bivouac condensation, and wind shear at 3,800m.",
					BodyParagraphs: []string{
						"Autumn alpine traverses offer crisp, stable rock and vacant huts, but once November approaches, the margin between triumphant ascent and frozen emergency narrows to a few hours of daylight.",
						"Negotiating the exposed granite ribs of the Schreckhorn requires meticulous crampon technique over verglas-glazed slabs. With gusting winds pushing forty knots, rope management becomes a deliberate meditation.",
						"Huddled inside a single-wall dyneema bivy sack as barometric pressure plunged through the floor, the stove hissed quietly, melting blue glacial ice for essential hydration.",
					},
					KeyTakeaway: "Unflinching mental composure and rigid gear routines are the true safety anchors on high exposed ridges.",
				},
				{
					ID:       "ultralight-pack-physics",
					Title:    "The Physics of Ultralight Pack Baseweight on Technical Rock",
					Date:     "Nov 14, 2025",
					ReadTime: "6 min read",
					Category: "Gear Science",
					Tags:     []string{"Ultralight", "Materials", "Physics"},
					Excerpt:  "Analyzing how shaving three kilograms of baseweight alters center-of-gravity dynamics, friction coefficient, and forearm fatigue on vertical granite.",
					BodyParagraphs: []string{
						"Mountaineering lore once dictated that durability required heavy canvas and steel. Modern composite metallurgy and molecular polyethylene (UHMWPE) turn this paradigm on its head.",
						"When carrying eight kilograms versus fifteen kilograms up continuous 5.10 pitches, the climber's center of mass stays significantly closer to the natural vertical wall axis, saving critical finger grip strength.",
						"We break down thermal insulation ratings per gram of down fill and the structural integrity of carbon-reinforced frames under severe torsional loads.",
					},
					KeyTakeaway: "Every hundred grams shed from baseweight directly translates to increased speed, security, and endurance on technical terrain.",
				},
				{
					ID:       "navigating-whiteouts",
					Title:    "Navigating Whiteouts: Magnetic Declination and Altimeter Drift",
					Date:     "Sep 19, 2025",
					ReadTime: "7 min read",
					Category: "Navigation",
					Tags:     []string{"Cartography", "Safety", "Survival"},
					Excerpt:  "Practical field navigation when GPS satellites fail, battery voltages drop in -25°C, and whiteout conditions erase the horizon completely.",
					BodyParagraphs: []string{
						"In a total whiteout, the boundary between snow beneath your boots and the sky above dissolves completely. Vertigo sets in within minutes without visual reference points.",
						"By cross-referencing temperature-compensated barometric altimeter readouts with topographical contour lines and calibrated magnetic compass bearings, an experienced mountaineer can march blind with deadly precision.",
						"Pacing beads and rhythmic step counts maintain distance awareness across featureless glacial plateaus, keeping teams safe from hidden crevasse fields.",
					},
					KeyTakeaway: "Analog navigation fundamentals remain the ultimate fail-safe when electronic displays freeze and satellites drop.",
				},
				{
					ID:       "stoves-subzero-thermodynamics",
					Title:    "Thermodynamics of Inverted Canister Burners at Sub-Zero",
					Date:     "Jul 28, 2025",
					ReadTime: "5 min read",
					Category: "Expedition Tech",
					Tags:     []string{"Thermodynamics", "Survival", "Equipment"},
					Excerpt:  "Why standard butane canisters sputter out below freezing, and how inverted liquid-feed preheat loops ensure reliable snow melting at -20°C.",
					BodyParagraphs: []string{
						"At low temperatures, the vapor pressure of butane drops below atmospheric threshold, rendering upright canister stoves entirely useless just when hot water is vital for survival.",
						"Inverting the fuel canister feeds the compressed gas mixture as a liquid through a brass preheat tube positioned directly over the flame, where heat vaporizes it before combustion.",
						"Our thermal imaging data showcases flame efficiency variances across wind shields, confirming optimal pot heat-exchanger fin configurations for maximum fuel savings.",
					},
					KeyTakeaway: "Liquid-feed preheat systems guarantee stove operation in sub-zero winter bivouacs.",
				},
			},
		},

		// 4. Specialty Coffee Science & Roasting
		{
			Category: "Specialty Coffee & Extraction Dynamics",
			BlogTitles: []string{
				"Origin & Extraction",
				"The Sensory Cupping",
				"Pour & Bloom",
				"Micro-Lot Dispatch",
				"Refractometer Notes",
				"Terroir & Brew",
			},
			Taglines: []string{
				"Exploring extraction kinetics, water mineral chemistry, and small-batch roasting thermodynamics.",
				"Notes on single-origin terroir, anaerobic fermentations, and sensory calibration.",
				"Dispatches from high-elevation coffee estates, cupping tables, and precision grind distributions.",
			},
			Authors: []string{
				"Claire Beauchamp",
				"Sophie Dubois",
				"Kenji Sato",
				"Arthur Pendelton",
				"Elena Rossi",
			},
			Roles: []string{
				"Licensed Q-Grader & Specialty Coffee Roaster",
				"Extraction Chemist & Sensor Analyst",
				"Green Coffee Sourcing Director",
				"Artisan Roastery Founder & Barista Trainer",
			},
			Locations: []string{
				"Melbourne, Australia",
				"Kyoto, Japan",
				"Portland, Oregon",
				"Oslo, Norway",
				"Copenhagen, Denmark",
			},
			Bios: []string{
				"Dedicated to unlocking the aromatic complexities of heirloom Ethiopian and Gesha micro-lots through scientific extraction rigor.",
				"Investigating how mineral ionic bonds in brew water selectively extract organic acids and aromatic volatile esters.",
				"Bridging origin farming sustainability with precision roasting profiles in small, direct-trade micro-lots.",
			},
			ColorAccents: []colorPair{
				{Accent: "#f59e0b", Secondary: "#b45309", Glow: "rgba(245, 158, 11, 0.14)"}, // Warm Amber
				{Accent: "#d97706", Secondary: "#92400e", Glow: "rgba(217, 119, 6, 0.14)"}, // Roasted Caramel
				{Accent: "#10b981", Secondary: "#047857", Glow: "rgba(16, 185, 129, 0.14)"}, // Green Bean Emerald
			},
			Articles: []Article{
				{
					ID:       "bimodal-particle-burrs",
					Title:    "Bimodal Particle Distribution in Modern Flat Burrs",
					Date:     "Jan 15, 2026",
					ReadTime: "7 min read",
					Category: "Extraction",
					Tags:     []string{"Grinder", "Extraction", "Science", "Espresso"},
					Excerpt:  "How laser-cut unimodal and bimodal geometric burr profiles influence extraction uniformity, fines migration, and flavor clarity in high-extraction pour-overs.",
					BodyParagraphs: []string{
						"The holy grail of modern coffee brewing has long been uniform particle geometry. Yet the microscopic fines produced during bean shattering play a dual role: providing body while risking astringency through channel clogging.",
						"Using laser diffraction granulometry, we compare 98mm SSP burr sets against traditional conical geometries, observing how distinct cutting angles reduce the fines peak by over 40%.",
						"The result in the cup is striking: sparkling floral clarity, vibrant malic acidity, and transparent mouthfeel that allows delicate washed Gesha notes to shine unimpeded.",
					},
					KeyTakeaway: "Minimizing microscopic fines allows higher extraction yields without introducing harsh astringent tannins.",
				},
				{
					ID:       "water-mineral-chemistry",
					Title:    "Water Chemistry: Magnesium Chelation and Bicarbonate Buffers",
					Date:     "Nov 20, 2025",
					ReadTime: "9 min read",
					Category: "Chemistry",
					Tags:     []string{"Water", "Chemistry", "TDS", "Flavor"},
					Excerpt:  "Dialing remineralized distilled water recipes. How calcium and magnesium cations selectively bind with fruit acids versus roasty phenols.",
					BodyParagraphs: []string{
						"Coffee is 98.5% water, yet many cafes invest thousands in equipment while neglecting their solvent chemistry. Municipal tap water carries heavy bicarbonate buffers that neutralize delicate floral acidity.",
						"Magnesium cations (Mg2+) exhibit higher charge density, pulling fruity volatile organic compounds out of the grounds with greater affinity than calcium ions.",
						"By formulating a custom 80 ppm total hardness profile with a 2:1 magnesium-to-calcium ratio and 25 ppm alkalinity, brew clarity and sweet aftertaste are dramatically heightened.",
					},
					KeyTakeaway: "Formulating a tailored mineral water recipe unlocks vibrant fruit acids that standard tap water completely masks.",
				},
				{
					ID:       "roast-thermodynamics-maillard",
					Title:    "Thermodynamic Profiles during the Maillard Phase in Roasting",
					Date:     "Oct 03, 2025",
					ReadTime: "6 min read",
					Category: "Roasting",
					Tags:     []string{"Roasting", "Thermodynamics", "Chemistry"},
					Excerpt:  "Rate of rise (RoR) management between yellowing and first crack. Preserving organic citric acids while building complex aromatic sugars.",
					BodyParagraphs: []string{
						"The Maillard reaction represents the transformative phase where reducing sugars and amino acids combine into hundreds of new aromatic melanoidins and flavor precursors.",
						"Extending this phase develops velvety mouthfeel and caramel complexity, but spending too long bakes out delicate citric acidity, resulting in a flat, one-dimensional cup.",
						"Through continuous drum thermocouple tracking and non-linear airflow adjustments, we map the exact thermal momentum required to coast gracefully into first crack.",
					},
					KeyTakeaway: "Carefully tapering the Rate of Rise preserves lively natural acidity while fully caramelizing complex sugars.",
				},
				{
					ID:       "anaerobic-maceration-ferment",
					Title:    "Anaerobic Maceration: Flavor Compounds and Yeast Inoculation",
					Date:     "Aug 11, 2025",
					ReadTime: "8 min read",
					Category: "Origin",
					Tags:     []string{"Fermentation", "Micro-Lot", "Terroir"},
					Excerpt:  "Sealing harvested coffee cherries inside oxygen-depleted stainless steel bioreactors to produce tropical ester notes like passionfruit and wild strawberry.",
					BodyParagraphs: []string{
						"Traditional coffee processing relies on natural ambient yeasts and open fermentation tanks. Controlled anaerobic fermentation replaces ambient air with carbon dioxide, suppressing aerobic mold.",
						"Under these hypoxic conditions, lactic acid bacteria and specific wine yeast strains proliferate, producing high concentrations of aromatic esters and volatile fruit compounds.",
						"The cup profile shifts toward dense tropical fruit, candied wine, and dark chocolate notes that transform how origin character is perceived globally.",
					},
					KeyTakeaway: "Hypoxic bio-fermentation crafts concentrated aromatic esters that elevate specialty micro-lots into distinct tasting experiences.",
				},
			},
		},

		// 5. Analogue Photography & Optical Craft
		{
			Category: "Analogue Optics & Street Documentary",
			BlogTitles: []string{
				"Silver Halide",
				"Zone System Notes",
				"Monochrome Grain",
				"The 35mm Frame",
				"Aperture & Emulsion",
				"Light & Silver",
			},
			Taglines: []string{
				"Reflections on traditional darkroom chemistry, mechanical rangefinders, and street documentary light.",
				"Notes on black-and-white emulsion physics, manual optics, and silver gelatin craft.",
				"Documenting quiet city corners, medium-format negatives, and classic German optical designs.",
			},
			Authors: []string{
				"Arthur Pendelton",
				"David Sterling",
				"Kenji Sato",
				"Tobias Vance",
				"Marcus Thorne",
			},
			Roles: []string{
				"Independent Documentary Photographer & Master Darkroom Printer",
				"Mechanical Camera Restorer & Optical Collector",
				"Medium Format Landscape Photographer",
				"Street Visualist & Film Emulsion Specialist",
			},
			Locations: []string{
				"Edinburgh, Scotland",
				"Kyoto, Japan",
				"Berlin, Germany",
				"San Francisco, CA",
				"Vienna, Austria",
			},
			Bios: []string{
				"Dedicated to the deliberate slowness of mechanical rangefinders, manual focus lenses, and hand-processed silver halides.",
				"Restoring vintage brass shutters, testing historic lens designs, and printing deep monochromatic tones on fiber-based papers.",
				"Wandering rain-slicked city streets at twilight with a 35mm f/1.4 lens and high-grain black-and-white emulsions.",
			},
			ColorAccents: []colorPair{
				{Accent: "#e2e8f0", Secondary: "#64748b", Glow: "rgba(226, 232, 240, 0.14)"}, // Silver Grain
				{Accent: "#fbbf24", Secondary: "#d97706", Glow: "rgba(251, 191, 36, 0.14)"}, // Warm Darkroom Amber
				{Accent: "#94a3b8", Secondary: "#475569", Glow: "rgba(148, 163, 184, 0.14)"}, // Monochrome Neutral
			},
			Articles: []Article{
				{
					ID:       "calibrating-pyrocat-hd",
					Title:    "Calibrating Pyrocat-HD for High-Contrast Medium Format Negatives",
					Date:     "Jan 09, 2026",
					ReadTime: "7 min read",
					Category: "Darkroom",
					Tags:     []string{"Darkroom", "Chemistry", "Medium Format", "Film"},
					Excerpt:  "Compensating developer chemistry for extreme dynamic range. How pyrocatechin tanning actions preserve delicate highlight tonality under midday sun.",
					BodyParagraphs: []string{
						"High contrast scenes have long been the bane of black-and-white film. Developing for shadow detail frequently blocks dense highlights on the negative, causing skies to blow out irreversibly.",
						"Staining developers like Pyrocat-HD use pyrocatechin to harden gelatin directly proportional to silver density, creating a proportional yellow-brown dye mask that acts as an optical filter during enlarger printing.",
						"The resulting negatives boast creamy micro-contrast in shadow values alongside breathtaking highlight separation, making fiber base wet prints come alive with luminous depth.",
					},
					KeyTakeaway: "Tanning staining developers maintain delicate cloud highlights without sacrificing deep, shadow detail.",
				},
				{
					ID:       "mechanical-shutter-precision",
					Title:    "Mechanical Shutter Precision in 1960s Rangefinders",
					Date:     "Nov 18, 2025",
					ReadTime: "8 min read",
					Category: "Mechanics",
					Tags:     []string{"Rangefinder", "Restoration", "Mechanics"},
					Excerpt:  "Disassembling clockwork escapements and measuring shutter curtain velocity using optical photodiode sensors to restore 1/1000s accuracy.",
					BodyParagraphs: []string{
						"Vintage mechanical camera shutters are marvels of miniature horology. Decades-old synthetic lubricants gum up gear teeth, causing 1/500th of a second to drag down to 1/250th.",
						"By cleaning tiny brass pinion gears in an ultrasonic benzine bath and re-lubricating with synthetic watch oils, escapement timings return to factory tolerances.",
						"Using dual-photodiode oscilloscope rigs, we measure curtain bounce and travel uniformity across the 36x24mm focal gate with millisecond precision.",
					},
					KeyTakeaway: "Ultrasonic cleaning and high-grade horological lubricants restore mechanical shutters to pinpoint factory tolerances.",
				},
				{
					ID:       "double-gauss-optical-rendition",
					Title:    "The Rendition of Double-Gauss Lenses Under Grazing Light",
					Date:     "Sep 27, 2025",
					ReadTime: "6 min read",
					Category: "Optics",
					Tags:     []string{"Optics", "Lenses", "Aesthetics"},
					Excerpt:  "Why modern multi-element aspherical lenses often lack the emotional depth and micro-contrast rendering of vintage symmetric double-Gauss formulas.",
					BodyParagraphs: []string{
						"Modern computer-designed lenses strive for zero aberrations, perfectly flat fields, and edge-to-edge clinical sharpness. Yet many fine art photographers feel something soulful was lost.",
						"Classic symmetrical six-element double-Gauss formulas allow gentle spherical aberrations wide open, yielding smooth fall-off into out-of-focus background planes without harsh onion-ring artifacts.",
						"When raking golden hour sunlight strikes the untreated glass surfaces, flare is embraced not as a defect, but as an expressive painting medium of atmosphere and luminescence.",
					},
					KeyTakeaway: "Subtle optical aberrations in classic double-Gauss designs impart distinct dimensional personality to portraits.",
				},
				{
					ID:       "pushing-trix-to-3200",
					Title:    "Street Documentation in Dusk: Pushing Tri-X to 3200",
					Date:     "Jul 19, 2025",
					ReadTime: "5 min read",
					Category: "Street",
					Tags:     []string{"Street", "35mm", "Night Photography"},
					Excerpt:  "Embracing grit and stark contrast. Stand development protocols for extracting shadow speed from Kodak Tri-X under neon city streetlamps.",
					BodyParagraphs: []string{
						"Shooting hand-held documentary photography on nighttime streets requires shutter speeds of at least 1/60th second at f/1.4, demanding an effective sensitivity of ISO 3200.",
						"Rather than violently agitating standard high-energy developers—which produces golf-ball-sized grainy clumps—we turn to Rodinal in extreme 1:100 dilution with semi-stand development.",
						"Over an hour of passive immersion, developer molecules in high-density areas exhaust themselves, while fresh chemistry continues working in deep shadow shadows, preserving mood and punch.",
					},
					KeyTakeaway: "Dilute stand development tames harsh grain while coaxing shadow textures from pushed black-and-white emulsions.",
				},
			},
		},

		// 6. Binary Analysis & Embedded Security
		{
			Category: "Binary Analysis & Hardware Security",
			BlogTitles: []string{
				"Binary Trace",
				"Stack & Register",
				"Decompiled Insights",
				"Low-Level Safety",
				"Opcode Dispatch",
				"Firmware Dissected",
			},
			Taglines: []string{
				"Notes on reverse engineering, firmware exploitation, memory safety invariants, and embedded silicon security.",
				"Exploring hardware glitching, control-flow integrity, and binary vulnerability research.",
				"Dispatches from decompilation pipelines, bare-metal microcontrollers, and memory allocators.",
			},
			Authors: []string{
				"Elena Rostova",
				"Viktor Vance",
				"Damian Cross",
				"Julian Mercer",
				"Nora Dahl",
			},
			Roles: []string{
				"Senior Vulnerability Researcher & Binary Analyst",
				"Firmware Security Architect",
				"Hardware Reverse Engineer & Cryptanalyst",
				"Low-Level Exploit Mitigations Specialist",
			},
			Locations: []string{
				"Prague, Czech Republic",
				"Munich, Germany",
				"Seattle, WA",
				"Tallinn, Estonia",
				"Austin, TX",
			},
			Bios: []string{
				"Probing the boundaries where hardware physics collides with software invariants, uncovering undocumented microcontroller behavior.",
				"Decompiling embedded firmware binaries and designing formal verification models for high-assurance systems.",
				"Dedicated to hardware glitching, side-channel analysis, and enforcing strict compile-time memory safety.",
			},
			ColorAccents: []colorPair{
				{Accent: "#10b981", Secondary: "#059669", Glow: "rgba(16, 185, 129, 0.14)"}, // Terminal Green
				{Accent: "#06b6d4", Secondary: "#0891b2", Glow: "rgba(6, 182, 212, 0.14)"}, // Cyan Matrix
				{Accent: "#f43f5e", Secondary: "#e11d48", Glow: "rgba(244, 63, 94, 0.14)"}, // Exploit Crimson
			},
			Articles: []Article{
				{
					ID:       "fault-injection-bootloader",
					Title:    "Auditing Microcontroller Memory Protections via Clock Glitching",
					Date:     "Jan 19, 2026",
					ReadTime: "8 min read",
					Category: "Hardware",
					Tags:     []string{"Fault Injection", "Hardware", "Bootloader", "Glitching"},
					Excerpt:  "Inducing momentary voltage dips on VDD during cryptographic public key checks to skip branch instructions and execute unsigned firmware.",
					BodyParagraphs: []string{
						"Modern secure microcontrollers claim robust root-of-trust protection via hardware cryptographic engines. However, software verification routines inevitably rely on conditional jump instructions like CBZ or BNE.",
						"By inserting a brief 20-nanosecond ground pulse on the core supply rail during public key verification, we trigger an instruction decode error, causing the processor to interpret the conditional branch as a benign NOP.",
						"We discuss layout counter-measures: on-die supply voltage monitors, redundant randomized verification steps, and hardware watchdog interlocks.",
					},
					KeyTakeaway: "Software security checks alone cannot withstand precise clock and power supply fault injection attacks.",
				},
				{
					ID:       "cfi-bypass-llvm",
					Title:    "Evaluating Control Flow Integrity Implementations in Modern LLVM",
					Date:     "Nov 11, 2025",
					ReadTime: "7 min read",
					Category: "Compilers",
					Tags:     []string{"LLVM", "CFI", "Security", "Compilers"},
					Excerpt:  "Assessing forward-edge indirect call checks and backward-edge shadow stacks against sophisticated Return-Oriented Programming (ROP) gadgets.",
					BodyParagraphs: []string{
						"Control Flow Integrity (CFI) aims to confine program execution to a statically determined graph. Clang's Forward-Edge CFI enforces type-based checks before indirect virtual method calls.",
						"Through carefully crafted trampoline gadgets in shared dynamic libraries, we evaluate how loose function signature equivalence can leave exploitable call targets.",
						"Pairing compile-time CFI with hardware-enforced shadow stacks (such as Intel CET and ARM PAC) raises exploit development costs to near-impossible heights.",
					},
					KeyTakeaway: "Hardware-assisted shadow stacks combined with strict LLVM CFI provide resilient defense against ROP chains.",
				},
				{
					ID:       "ghidra-headless-iot",
					Title:    "Automated Headless Ghidra Analysis of Monolithic IoT Firmware",
					Date:     "Sep 05, 2025",
					ReadTime: "6 min read",
					Category: "Reverse Eng",
					Tags:     []string{"Ghidra", "IoT", "Automation", "Firmware"},
					Excerpt:  "Building Python scripts to automatically detect base addresses, identify interrupt vector tables, and reconstruct struct definitions from raw binary blobs.",
					BodyParagraphs: []string{
						"Monolithic RTOS firmware images lack ELF headers, memory segment tables, and symbol symbols, making manual reverse engineering tedious and prone to false starts.",
						"Using headless Ghidra scripts, we scan ARM Cortex-M binary dumps for reset vector pointers, infer RAM and flash boundaries, and label peripheral MMIO register mappings automatically.",
						"This automated pipeline accelerates vulnerability triage across hundreds of consumer IoT devices from days to minutes.",
					},
					KeyTakeaway: "Heuristic-driven headless analysis scripts effortlessly recover structure from bare-metal monolithic firmware dumps.",
				},
				{
					ID:       "rust-vs-c-memory-invariants",
					Title:    "Static Analysis of Bare-Metal Memory Models in Rust vs C",
					Date:     "Jul 14, 2025",
					ReadTime: "9 min read",
					Category: "Languages",
					Tags:     []string{"Rust", "C", "Memory Safety", "Embedded"},
					Excerpt:  "How ownership semantics, affine types, and UnsafeCell invariants eliminate concurrency races without runtime garbage collection overhead.",
					BodyParagraphs: []string{
						"Embedded developers have long relied on C for complete hardware control, accepting the constant hazard of buffer overflows, dangling pointers, and race conditions.",
						"Rust's borrow checker enforces compile-time ownership rules that guarantee exclusive mutable access, making data races physically impossible across multi-threaded execution contexts.",
						"We demonstrate how safe zero-cost abstractions model peripheral registers with type-state patterns, catching hardware state violations before code ever hits silicon.",
					},
					KeyTakeaway: "Compile-time ownership semantics completely eliminate memory corruption hazards in embedded real-time systems.",
				},
			},
		},

		// 7. Computational Ecology & Permaculture
		{
			Category: "Computational Ecology & Botany",
			BlogTitles: []string{
				"Soil & Canopy",
				"Flora & Sensor",
				"Urban Canopy Log",
				"Symbiosis Dispatch",
				"The Living Biome",
				"Micro-Climate Notes",
			},
			Taglines: []string{
				"Documenting urban permaculture, low-power LoRaWAN environmental meshes, and soil microbial health.",
				"Notes on botanical taxonomy, passive thermal micro-climates, and ecological data sensing.",
				"Dispatches from restorative agriculture, plant acoustics, and closed-loop soil composting.",
			},
			Authors: []string{
				"Nora Dahl",
				"Fiona Gallagher",
				"Rowan Mercer",
				"Linnea Strand",
				"Claire Beauchamp",
			},
			Roles: []string{
				"Ecological Data Scientist & Permaculture Designer",
				"Urban Botanist & Sensor Mesh Architect",
				"Soil Microbiome Researcher",
				"Passive Solar Greenhouse Engineer",
			},
			Locations: []string{
				"Portland, Oregon",
				"Vancouver, BC",
				"Freiburg, Germany",
				"Melbourne, Australia",
				"Kyoto, Japan",
			},
			Bios: []string{
				"Bridging digital embedded sensors with living ecological networks to build resilient urban food systems.",
				"Tracking mycorrhizal fungal networks, soil electrical conductivity, and rainwater thermal storage.",
				"Passionate about native perennial polycultures, biochar carbon sequestration, and bio-acoustic telemetry.",
			},
			ColorAccents: []colorPair{
				{Accent: "#34d399", Secondary: "#059669", Glow: "rgba(52, 211, 153, 0.14)"}, // Canopy Green
				{Accent: "#84cc16", Secondary: "#4d7c0f", Glow: "rgba(132, 204, 22, 0.14)"}, // Fresh Sprout
				{Accent: "#14b8a6", Secondary: "#0f766e", Glow: "rgba(20, 184, 166, 0.14)"}, // Teal Moss
			},
			Articles: []Article{
				{
					ID:       "lorawan-soil-profiling",
					Title:    "Autonomous Soil Moisture Profiling via LoRaWAN Meshes",
					Date:     "Jan 04, 2026",
					ReadTime: "7 min read",
					Category: "Sensors",
					Tags:     []string{"LoRaWAN", "IoT", "Sensors", "Agriculture"},
					Excerpt:  "Deploying low-power capacitive sensors across terraced garden micro-climates to map subterranean moisture retention without battery maintenance.",
					BodyParagraphs: []string{
						"Traditional agricultural irrigation relies on crude timers that waste water or under-hydrate deep taproots during hot summer heatwaves.",
						"By distributing low-power LoRaWAN sensor nodes outfitted with frequency-domain capacitive probes, we stream volumetric soil water content from multiple root depths every fifteen minutes.",
						"Powered by miniature solar harvesters with supercapacitor storage, these autonomous sentinels provide years of maintenance-free environmental intelligence.",
					},
					KeyTakeaway: "Subterranean sensor telemetry optimizes irrigation schedules while conserving up to 45% of municipal water.",
				},
				{
					ID:       "mycorrhizal-fungal-networks",
					Title:    "Microbial Inoculation and Mycorrhizal Networks in Raised Beds",
					Date:     "Nov 02, 2025",
					ReadTime: "8 min read",
					Category: "Soil Health",
					Tags:     []string{"Microbiome", "Permaculture", "Biology"},
					Excerpt:  "How arbuscular mycorrhizal fungi extend root surface area by 700%, chelating insoluble minerals and building living soil structure.",
					BodyParagraphs: []string{
						"Industrial fertilizers flood soil with synthetic nitrates, destroying beneficial fungal hyphae and turning vibrant soil into dead inert dirt.",
						"By introducing diverse arbuscular fungal spores alongside biochar charged with compost tea, we re-establish the subterranean trade network between plant sugars and rock-bound minerals.",
						"Microscopic soil scans confirm heightened nutrient density in heirloom crops, alongside extraordinary drought resilience during extreme heatwaves.",
					},
					KeyTakeaway: "Living mycorrhizal hyphae form the biological backbone of nutrient-dense, drought-resistant cultivation.",
				},
				{
					ID:       "passive-solar-greenhouse",
					Title:    "Passive Solar Greenhouses: Thermal Mass Sizing for Sub-Zero Climates",
					Date:     "Sep 14, 2025",
					ReadTime: "6 min read",
					Category: "Greenhouse",
					Tags:     []string{"Solar", "Thermal Mass", "Design"},
					Excerpt:  "Calculating water barrel heat storage, earth berming, and insulated north walls to grow sub-tropical greens throughout freezing northern winters without heaters.",
					BodyParagraphs: []string{
						"Heating winter greenhouses with propane or electricity creates fragile, energy-hungry dependencies that fail during severe winter storms.",
						"Passive solar architecture utilizes steep south-facing glazed surfaces to capture low winter sun, storing thermal energy in dense black water drums stacked against insulated north walls.",
						"Throughout sub-zero nights, this thermal mass slowly releases heat, keeping indoor temperatures well above freezing without burning a single watt of grid electricity.",
					},
					KeyTakeaway: "Calculated thermal mass and earth berming sustain winter greenhouse production completely off-grid.",
				},
				{
					ID:       "bioacoustic-bird-tinyml",
					Title:    "Acoustic Biodiversity Monitoring with TinyML Spectrograms",
					Date:     "Jul 08, 2025",
					ReadTime: "5 min read",
					Category: "Bio-acoustics",
					Tags:     []string{"TinyML", "Ecology", "Edge AI"},
					Excerpt:  "Classifying bird calls and pollinator wingbeat frequencies in urban rooftop habitats using low-power edge microcontrollers running quantized neural networks.",
					BodyParagraphs: []string{
						"Assessing the ecological success of urban rewilding initiatives requires continuous, objective species census data that manual observation cannot match.",
						"We place waterproof acoustic monitors in city tree canopies, processing 16-bit audio through FFT spectrogram pipelines on Cortex-M4 chips running quantized 8-bit convolutional networks.",
						"The system detects over 40 native species by song profile, verifying the rapid return of predatory pollinators to rooftop meadow installations.",
					},
					KeyTakeaway: "Edge TinyML spectrogram models provide non-intrusive 24/7 ecological censuses in complex habitats.",
				},
			},
		},

		// 8. High-Fidelity Audio & Vacuum Tube Acoustics
		{
			Category: "High-Fidelity Audio & Acoustic Engineering",
			BlogTitles: []string{
				"Harmonic Resonance",
				"Acoustic Plane",
				"The Tube Stage",
				"Hi-Fi Craft & Design",
				"Analog Waveform",
				"Linear Decibel Log",
			},
			Taglines: []string{
				"Explorations in single-ended triode amplification, room impulse responses, and discrete DAC topologies.",
				"Notes on high-resolution transducers, transformer winding geometry, and listening acoustics.",
				"Dispatches from vacuum tube metallurgy, analog master recordings, and physical psychoacoustics.",
			},
			Authors: []string{
				"Marcus Sterling",
				"Stefan Becker",
				"Oliver Vance",
				"Julian Mercer",
				"Arthur Pendelton",
			},
			Roles: []string{
				"Acoustical Engineer & Audio Equipment Designer",
				"Vacuum Tube Circuit Specialist & Transformer Winder",
				"Mastering Engineer & Studio Designer",
				"Analog Electronics Researcher",
			},
			Locations: []string{
				"Munich, Germany",
				"Tokyo, Japan",
				"London, UK",
				"Stockholm, Sweden",
				"San Francisco, CA",
			},
			Bios: []string{
				"Dedicated to the preservation of natural harmonic timbre through direct-heated triodes and phase-aligned loudspeaker design.",
				"Designing bespoke studio monitoring environments, measuring room standing waves, and crafting hand-wound permalloy output transformers.",
				"Pursuing the pure, organic reproduction of acoustic music through minimalist signal paths and discrete ladder networks.",
			},
			ColorAccents: []colorPair{
				{Accent: "#f59e0b", Secondary: "#d97706", Glow: "rgba(245, 158, 11, 0.14)"}, // Tube Glow Amber
				{Accent: "#a855f7", Secondary: "#7e22ce", Glow: "rgba(168, 85, 247, 0.14)"}, // Purple Ray
				{Accent: "#38bdf8", Secondary: "#0284c7", Glow: "rgba(56, 189, 248, 0.14)"}, // Electric Blue
			},
			Articles: []Article{
				{
					ID:       "second-harmonic-triode-sound",
					Title:    "Second-Harmonic Distribution in Single-Ended Triode Preamps",
					Date:     "Jan 10, 2026",
					ReadTime: "8 min read",
					Category: "Amplification",
					Tags:     []string{"Vacuum Tubes", "Harmonics", "Circuits", "Hi-Fi"},
					Excerpt:  "The psychoacoustics of low-order harmonic profiles. Why human hearing perceives benign second harmonics as spatial depth, warmth, and realism.",
					BodyParagraphs: []string{
						"Solid-state amplifiers boast vanishingly small total harmonic distortion (THD) figures on paper, yet frequently sound dry, sterile, and fatiguing during extended listening sessions.",
						"Direct-heated triodes operate with gentle square-law transfer curves, producing an orderly decay of second-order harmonic overtones that mimic the natural acoustic overtone series of acoustic instruments.",
						"This harmonious distribution psychoacoustically aids the human brain in resolving ambient room cues, granting vocals and strings palpably three-dimensional presence.",
					},
					KeyTakeaway: "Linear low-order harmonic spectra align with human hearing mechanics to create fatigue-free natural imaging.",
				},
				{
					ID:       "room-mode-cancellation",
					Title:    "Taming Sub-60Hz Standing Waves via Tuned Helmholtz Resonators",
					Date:     "Nov 25, 2025",
					ReadTime: "7 min read",
					Category: "Acoustics",
					Tags:     []string{"Room Acoustics", "Physics", "Bass"},
					Excerpt:  "Why passive porous fiberglass traps fail below 60Hz, and how custom calculated resonant wooden cavities absorb room pressure nodes.",
					BodyParagraphs: []string{
						"Small listening rooms suffer from severe low-frequency resonances dictated by their physical boundary dimensions. Bass notes boom uncontrollably at mode peaks while canceling into silence at nulls.",
						"Because sound waves at 40Hz stretch nearly nine meters in length, velocity-based acoustic absorbers would need to be several feet thick to exert meaningful damping.",
						"Tuned Helmholtz resonators and perforated diaphragmatic membrane traps act directly on high-pressure boundary corners, converting destructive acoustic energy into harmless internal thermal movement.",
					},
					KeyTakeaway: "Pressure-based resonant traps provide targeted absorption of troublesome sub-60Hz room standing modes.",
				},
				{
					ID:       "r2r-ladder-vs-deltasigma",
					Title:    "Discrete R-2R Resistor Ladder DACs vs Delta-Sigma Architectures",
					Date:     "Sep 18, 2025",
					ReadTime: "9 min read",
					Category: "Digital Audio",
					Tags:     []string{"DAC", "Digital Audio", "Circuits"},
					Excerpt:  "Comparing transient impulse responses, zero-feedback resistor matching, and high-frequency noise modulation between converter architectures.",
					BodyParagraphs: []string{
						"Delta-Sigma converters dominate commercial electronics by converting multi-bit samples into ultra-high-speed 1-bit streams, filtering out quantizing noise via aggressive noise shaping.",
						"In contrast, discrete R-2R ladder architectures utilize hundreds of precision thin-film 0.01% resistors to directly convert raw binary words into analog voltages without aggressive digital decimation filters.",
						"The resulting analog waveform preserves immaculate leading-edge transient impact and realistic acoustic decay without high-frequency ringing artifacts.",
					},
					KeyTakeaway: "Discrete resistor ladders maintain immaculate transient timing without digital pre-ringing artifacts.",
				},
				{
					ID:       "transformer-saturation-permalloy",
					Title:    "Output Transformer Permeability and Core Saturation",
					Date:     "Jul 21, 2025",
					ReadTime: "6 min read",
					Category: "Transformers",
					Tags:     []string{"Transformers", "Metallurgy", "Magnetics"},
					Excerpt:  "Balancing nickel-iron permalloy core permeability against DC flux bias to extend frequency response cleanly from 10Hz to 65kHz.",
					BodyParagraphs: []string{
						"The output transformer is the true heart and soul of any valve amplifier, coupling high-voltage plate impedances down to low-resistance loudspeaker coils.",
						"Standard silicon steel cores offer high magnetic saturation but exhibit hysteresis losses at low signal levels. High-nickel permalloy laminations provide astonishing initial permeability, conveying gossamer micro-details.",
						"By introducing microscopic air gaps in single-ended configurations and interleaving primary and secondary winding layers, magnetic leakage inductance is minimized across the entire audio band.",
					},
					KeyTakeaway: "Precision winding interleaving and permalloy metallurgy yield linear bandwidth and effortless dynamic drive.",
				},
			},
		},
	}
}

// GenerateSite creates a randomized, unique, high-entropy mask blog HTML and metadata.
func GenerateSite() (string, *SiteMeta, error) {
	themes := getThemes()
	themeIdx := secureRandInt(len(themes))
	theme := themes[themeIdx]

	title := theme.BlogTitles[secureRandInt(len(theme.BlogTitles))]
	tagline := theme.Taglines[secureRandInt(len(theme.Taglines))]
	author := theme.Authors[secureRandInt(len(theme.Authors))]
	role := theme.Roles[secureRandInt(len(theme.Roles))]
	location := theme.Locations[secureRandInt(len(theme.Locations))]
	bio := theme.Bios[secureRandInt(len(theme.Bios))]
	color := theme.ColorAccents[secureRandInt(len(theme.ColorAccents))]

	// Select 3 or 4 articles randomly
	articlesPool := make([]Article, len(theme.Articles))
	copy(articlesPool, theme.Articles)

	// Shuffle
	for i := len(articlesPool) - 1; i > 0; i-- {
		j := secureRandInt(i + 1)
		articlesPool[i], articlesPool[j] = articlesPool[j], articlesPool[i]
	}

	count := 3
	if len(articlesPool) >= 4 && secureRandInt(2) == 1 {
		count = 4
	}
	selectedArticles := articlesPool[:count]

	// Dark mode colors with slight randomness
	bgColors := []string{"#0b0f17", "#0a0d14", "#0d1117", "#0f141c", "#10141d"}
	surfaceColors := []string{"#111827", "#131b26", "#161e2e", "#151c28"}
	bgColor := bgColors[secureRandInt(len(bgColors))]
	surfaceColor := surfaceColors[secureRandInt(len(surfaceColors))]

	meta := &SiteMeta{
		BlogTitle:      title,
		Tagline:        tagline,
		AuthorName:     author,
		AuthorRole:     role,
		AuthorLocation: location,
		AuthorBio:      bio,
		Category:       theme.Category,
		AccentColor:    color.Accent,
		SecondaryColor: color.Secondary,
		AccentGlow:     color.Glow,
		BgColor:        bgColor,
		SurfaceColor:   surfaceColor,
		SurfaceHover:   "#1e293b",
		BorderColor:    "rgba(255, 255, 255, 0.08)",
		TextMain:       "#f8fafc",
		TextMuted:      "#94a3b8",
		ArticleCount:   len(selectedArticles),
		Articles:       selectedArticles,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	html := renderHTML(meta)
	return html, meta, nil
}

// GenerateAndWrite generates the random blog and writes it to targetDir/index.html.
func GenerateAndWrite(targetDir string) (*SiteMeta, error) {
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", targetDir, err)
	}

	html, meta, err := GenerateSite()
	if err != nil {
		return nil, err
	}

	dest := filepath.Join(targetDir, "index.html")
	if err := os.WriteFile(dest, []byte(html), 0644); err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", dest, err)
	}

	// Also write metadata for quick inspection
	metaFile := filepath.Join(targetDir, "mask_meta.json")
	_ = os.WriteFile(metaFile, []byte(fmt.Sprintf(
		`{"blogTitle":%q,"author":%q,"category":%q,"generatedAt":%q}`,
		meta.BlogTitle, meta.AuthorName, meta.Category, meta.GeneratedAt,
	)), 0644)

	return meta, nil
}

// ReadExistingMeta returns the meta description if mask_meta.json exists in targetDir.
func ReadExistingMeta(targetDir string) string {
	data, err := os.ReadFile(filepath.Join(targetDir, "mask_meta.json"))
	if err != nil {
		return ""
	}
	return string(data)
}

func renderHTML(m *SiteMeta) string {
	var b strings.Builder

	// Build articles JSON for client-side search & reader modal
	var jsArticles []string
	for _, a := range m.Articles {
		escapedTitle := strings.ReplaceAll(a.Title, `"`, `\"`)
		escapedExcerpt := strings.ReplaceAll(a.Excerpt, `"`, `\"`)
		escapedKeyTakeaway := strings.ReplaceAll(a.KeyTakeaway, `"`, `\"`)
		var pList []string
		for _, p := range a.BodyParagraphs {
			escapedP := strings.ReplaceAll(p, `"`, `\"`)
			pList = append(pList, fmt.Sprintf(`"%s"`, escapedP))
		}
		var tagList []string
		for _, t := range a.Tags {
			tagList = append(tagList, fmt.Sprintf(`"%s"`, t))
		}
		jsArticles = append(jsArticles, fmt.Sprintf(`{
			id: %q,
			title: "%s",
			date: %q,
			readTime: %q,
			category: %q,
			tags: [%s],
			excerpt: "%s",
			paragraphs: [%s],
			keyTakeaway: "%s"
		}`, a.ID, escapedTitle, a.Date, a.ReadTime, a.Category, strings.Join(tagList, ","), escapedExcerpt, strings.Join(pList, ","), escapedKeyTakeaway))
	}
	articlesJSON := "[" + strings.Join(jsArticles, ",") + "]"

	// Monogram
	authorInitials := ""
	parts := strings.Split(m.AuthorName, " ")
	for _, p := range parts {
		if len(p) > 0 {
			authorInitials += string(p[0])
		}
	}
	if len(authorInitials) > 2 {
		authorInitials = authorInitials[:2]
	}

	b.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s | %s</title>
    <meta name="description" content="%s">
    <meta name="author" content="%s">
    <meta property="og:title" content="%s">
    <meta property="og:description" content="%s">
    <meta property="og:type" content="website">
    <style>
        :root {
            --bg-color: %s;
            --surface-color: %s;
            --surface-hover: %s;
            --border-color: %s;
            --border-hover: %s;
            --text-main: %s;
            --text-muted: %s;
            --text-dim: #64748b;
            --accent: %s;
            --accent-sec: %s;
            --accent-glow: %s;
            --radius-md: 10px;
            --radius-lg: 16px;
        }

        [data-theme="light"] {
            --bg-color: #f8fafc;
            --surface-color: #ffffff;
            --surface-hover: #f1f5f9;
            --border-color: rgba(0, 0, 0, 0.08);
            --border-hover: rgba(0, 0, 0, 0.16);
            --text-main: #0f172a;
            --text-muted: #475569;
            --text-dim: #94a3b8;
            --accent: %s;
            --accent-glow: rgba(0, 0, 0, 0.05);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.65;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
            transition: background-color 0.25s ease, color 0.25s ease;
        }

        a {
            color: inherit;
            text-decoration: none;
            transition: color 0.2s ease;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 0 24px;
            width: 100%%;
        }

        /* Header */
        header {
            padding: 20px 0;
            border-bottom: 1px solid var(--border-color);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            position: sticky;
            top: 0;
            background-color: rgba(11, 15, 23, 0.85);
            z-index: 100;
        }

        [data-theme="light"] header {
            background-color: rgba(248, 250, 252, 0.88);
        }

        .nav-wrap {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 700;
            font-size: 1.15rem;
            letter-spacing: -0.02em;
        }

        .brand-avatar {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            background: linear-gradient(135deg, var(--accent), var(--accent-sec));
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 0.85rem;
            box-shadow: 0 4px 12px var(--accent-glow);
        }

        .nav-links {
            display: flex;
            align-items: center;
            gap: 20px;
            font-size: 0.9rem;
            color: var(--text-muted);
        }

        .nav-links a:hover {
            color: var(--accent);
        }

        .theme-toggle-btn {
            background: none;
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            width: 34px;
            height: 34px;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .theme-toggle-btn:hover {
            color: var(--accent);
            border-color: var(--accent);
        }

        /* Hero */
        .hero {
            padding: 56px 0 36px;
        }

        .hero-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 20px;
            background: var(--accent-glow);
            border: 1px solid rgba(255, 255, 255, 0.08);
            font-size: 0.78rem;
            font-weight: 600;
            color: var(--accent);
            margin-bottom: 16px;
            letter-spacing: 0.03em;
            text-transform: uppercase;
        }

        .hero h1 {
            font-size: 2.3rem;
            font-weight: 800;
            line-height: 1.25;
            letter-spacing: -0.03em;
            margin-bottom: 14px;
            background: linear-gradient(180deg, var(--text-main) 30%%, var(--text-muted) 100%%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .hero p {
            font-size: 1.05rem;
            color: var(--text-muted);
            max-width: 680px;
            line-height: 1.7;
            margin-bottom: 24px;
        }

        .author-card {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 16px 20px;
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            margin-bottom: 40px;
        }

        .author-meta h3 {
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text-main);
        }

        .author-meta p {
            font-size: 0.82rem;
            color: var(--text-muted);
            margin: 2px 0 0;
            line-height: 1.4;
        }

        .author-meta .loc {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            color: var(--text-dim);
            font-size: 0.76rem;
            margin-top: 4px;
        }

        /* Search Bar & Filter */
        .controls-row {
            display: flex;
            gap: 12px;
            align-items: center;
            margin-bottom: 28px;
            flex-wrap: wrap;
        }

        .search-box {
            position: relative;
            flex: 1;
            min-width: 220px;
        }

        .search-box input {
            width: 100%%;
            padding: 10px 14px 10px 38px;
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            color: var(--text-main);
            font-size: 0.88rem;
            outline: none;
            transition: all 0.2s ease;
        }

        .search-box input:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }

        .search-icon {
            position: absolute;
            left: 12px;
            top: 50%%;
            transform: translateY(-50%%);
            color: var(--text-dim);
            pointer-events: none;
        }

        /* Articles Grid */
        .articles-list {
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin-bottom: 60px;
        }

        .article-card {
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 24px;
            transition: all 0.25s ease;
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }

        .article-card:hover {
            border-color: var(--accent);
            transform: translateY(-2px);
            box-shadow: 0 12px 28px -8px rgba(0, 0, 0, 0.35);
        }

        .article-header {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.8rem;
            color: var(--text-dim);
            margin-bottom: 10px;
        }

        .category-badge {
            background: var(--accent-glow);
            color: var(--accent);
            font-size: 0.75rem;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 6px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .article-title {
            font-size: 1.28rem;
            font-weight: 700;
            line-height: 1.35;
            margin-bottom: 10px;
            letter-spacing: -0.015em;
            color: var(--text-main);
            transition: color 0.2s ease;
        }

        .article-card:hover .article-title {
            color: var(--accent);
        }

        .article-excerpt {
            font-size: 0.92rem;
            color: var(--text-muted);
            line-height: 1.6;
            margin-bottom: 16px;
        }

        .article-footer {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.82rem;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            padding-top: 14px;
        }

        .article-tags {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .tag {
            font-size: 0.74rem;
            color: var(--text-dim);
            background: rgba(255, 255, 255, 0.04);
            padding: 2px 8px;
            border-radius: 4px;
        }

        .read-btn {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            color: var(--accent);
            font-weight: 600;
            font-size: 0.82rem;
        }

        /* Reader Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(8px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 20px;
        }

        .modal-overlay.active {
            display: flex;
        }

        .modal-content {
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            max-width: 720px;
            width: 100%%;
            max-height: 90vh;
            overflow-y: auto;
            padding: 36px;
            box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
            position: relative;
        }

        .modal-close {
            position: absolute;
            top: 20px;
            right: 20px;
            background: none;
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            width: 32px;
            height: 32px;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-close:hover {
            color: var(--text-main);
            border-color: var(--accent);
        }

        .modal-body {
            margin-top: 20px;
            font-size: 0.98rem;
            line-height: 1.8;
            color: var(--text-main);
        }

        .modal-body p {
            margin-bottom: 18px;
        }

        .modal-takeaway {
            background: var(--accent-glow);
            border-left: 3px solid var(--accent);
            padding: 14px 18px;
            border-radius: 0 8px 8px 0;
            margin: 24px 0;
            font-size: 0.92rem;
            color: var(--text-main);
            font-style: italic;
        }

        /* Footer */
        footer {
            margin-top: auto;
            border-top: 1px solid var(--border-color);
            padding: 32px 0;
            font-size: 0.82rem;
            color: var(--text-dim);
            text-align: center;
        }

        .footer-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }

        @media (max-width: 640px) {
            .hero h1 {
                font-size: 1.8rem;
            }
            .author-card {
                flex-direction: column;
                align-items: flex-start;
            }
            .modal-content {
                padding: 24px 18px;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container nav-wrap">
            <div class="brand">
                <div class="brand-avatar">%s</div>
                <span>%s</span>
            </div>
            <div class="nav-links">
                <a href="#articles">Articles</a>
                <a href="#about">About</a>
                <button class="theme-toggle-btn" id="themeToggle" title="Toggle Theme" aria-label="Toggle Theme">
                    <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                    </svg>
                </button>
            </div>
        </div>
    </header>

    <main class="container">
        <section class="hero">
            <div class="hero-badge">%s</div>
            <h1>%s</h1>
            <p>%s</p>

            <div class="author-card" id="about">
                <div class="brand-avatar" style="width: 48px; height: 48px; font-size: 1.1rem; border-radius: 12px;">%s</div>
                <div class="author-meta">
                    <h3>%s</h3>
                    <p>%s</p>
                    <p style="font-size: 0.82rem; color: var(--text-muted); margin-top: 4px;">%s</p>
                    <div class="loc">
                        <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
                        </svg>
                        <span>%s</span>
                    </div>
                </div>
            </div>
        </section>

        <section id="articles">
            <div class="controls-row">
                <div class="search-box">
                    <svg class="search-icon" width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <input type="text" id="searchInput" placeholder="Filter articles by keyword or tag..." />
                </div>
            </div>

            <div class="articles-list" id="articlesList">
                <!-- Articles rendered via JS -->
            </div>
        </section>
    </main>

    <!-- Reading Modal -->
    <div class="modal-overlay" id="articleModal">
        <div class="modal-content">
            <button class="modal-close" id="modalClose">&times;</button>
            <div class="article-header" id="modalMeta"></div>
            <h2 class="article-title" id="modalTitle" style="font-size: 1.6rem; margin: 12px 0 16px;"></h2>
            <div class="modal-body" id="modalBody"></div>
            <div class="modal-takeaway" id="modalTakeaway"></div>
        </div>
    </div>

    <footer>
        <div class="container footer-content">
            <div>&copy; %d %s. Powered by independent publishing.</div>
            <div style="display: flex; gap: 16px;">
                <span>Dispatches &middot; %s</span>
                <span>All rights reserved</span>
            </div>
        </div>
    </footer>

    <script>
        const articles = %s;

        const articlesList = document.getElementById('articlesList');
        const searchInput = document.getElementById('searchInput');
        const modal = document.getElementById('articleModal');
        const modalClose = document.getElementById('modalClose');
        const modalTitle = document.getElementById('modalTitle');
        const modalMeta = document.getElementById('modalMeta');
        const modalBody = document.getElementById('modalBody');
        const modalTakeaway = document.getElementById('modalTakeaway');
        const themeToggle = document.getElementById('themeToggle');

        function renderArticles(filter = '') {
            articlesList.innerHTML = '';
            const q = filter.trim().toLowerCase();
            const matched = articles.filter(a => {
                if (!q) return true;
                return a.title.toLowerCase().includes(q) ||
                       a.excerpt.toLowerCase().includes(q) ||
                       a.tags.some(t => t.toLowerCase().includes(q)) ||
                       a.category.toLowerCase().includes(q);
            });

            if (matched.length === 0) {
                articlesList.innerHTML = '<div style="padding: 40px; text-align: center; color: var(--text-dim);">No dispatches found matching your search.</div>';
                return;
            }

            matched.forEach(a => {
                const card = document.createElement('article');
                card.className = 'article-card';
                card.onclick = () => openArticle(a.id);

                const tagsHtml = a.tags.map(t => '<span class="tag">' + t + '</span>').join('');

                card.innerHTML = 
                    '<div class="article-header">' +
                        '<span class="category-badge">' + a.category + '</span>' +
                        '<span>&bull;</span>' +
                        '<span>' + a.date + '</span>' +
                        '<span>&bull;</span>' +
                        '<span>' + a.readTime + '</span>' +
                    '</div>' +
                    '<h2 class="article-title">' + a.title + '</h2>' +
                    '<p class="article-excerpt">' + a.excerpt + '</p>' +
                    '<div class="article-footer">' +
                        '<div class="article-tags">' + tagsHtml + '</div>' +
                        '<span class="read-btn">Read full story &rarr;</span>' +
                    '</div>';
                articlesList.appendChild(card);
            });
        }

        function openArticle(id) {
            const a = articles.find(x => x.id === id);
            if (!a) return;

            modalMeta.innerHTML = 
                '<span class="category-badge">' + a.category + '</span>' +
                '<span>&bull;</span>' +
                '<span>' + a.date + '</span>' +
                '<span>&bull;</span>' +
                '<span>' + a.readTime + '</span>';

            modalTitle.textContent = a.title;

            modalBody.innerHTML = a.paragraphs.map(p => '<p>' + p + '</p>').join('');
            modalTakeaway.textContent = 'Key Takeaway: ' + a.keyTakeaway;

            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            modal.classList.remove('active');
            document.body.style.overflow = '';
        }

        modalClose.onclick = closeModal;
        modal.onclick = (e) => {
            if (e.target === modal) closeModal();
        };
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && modal.classList.contains('active')) {
                closeModal();
            }
        });

        searchInput.addEventListener('input', (e) => {
            renderArticles(e.target.value);
        });

        // Theme toggle
        let isLight = false;
        themeToggle.onclick = () => {
            isLight = !isLight;
            if (isLight) {
                document.documentElement.setAttribute('data-theme', 'light');
            } else {
                document.documentElement.removeAttribute('data-theme');
            }
        };

        // Initial render
        renderArticles();
    </script>
</body>
</html>`,
		m.BlogTitle, m.Tagline,
		m.Tagline,
		m.AuthorName,
		m.BlogTitle,
		m.Tagline,
		m.BgColor,
		m.SurfaceColor,
		m.SurfaceHover,
		m.BorderColor,
		m.AccentColor,
		m.TextMain,
		m.TextMuted,
		m.AccentColor,
		m.SecondaryColor,
		m.AccentGlow,
		m.SecondaryColor,
		authorInitials,
		m.BlogTitle,
		m.Category,
		m.BlogTitle,
		m.Tagline,
		authorInitials,
		m.AuthorName,
		m.AuthorRole,
		m.AuthorBio,
		m.AuthorLocation,
		time.Now().Year(),
		m.BlogTitle,
		m.Category,
		articlesJSON,
	))

	return b.String()
}
