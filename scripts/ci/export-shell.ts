const execSync = require("child_process").execSync;
const fs = require("fs");

const outputDir = process.argv[2];
if (!outputDir) {
    console.error('Output dir parameter is necessary');
    process.exit(1);
}

type Segment = string | [[string, string]];

type Line = Segment[];

type Recipe = {
    name: string
    body: Line[],
};

for (const file of fs
    .readdirSync(".")
    .filter((file) => file === ".justfile" || file.endsWith(".just"))) {
    const justfile = JSON.parse(
        execSync(`just --justfile ${file} --dump --dump-format=json`, {
            encoding: "utf-8",
        }),
    ) as { recipes: Recipe[] };

    Object.values(justfile.recipes).forEach(recipe => {
        const stream = fs.createWriteStream(`${outputDir}/${recipe.name}.sh`, 'utf8');
        recipe.body.forEach(line => {
            line.forEach(segment => {
                if (typeof segment === 'string') {
                    stream.write(segment)
                } else if (Array.isArray(segment) && Array.isArray(segment[0]) && (segment[0].length === 2) && (segment[0][0] === 'variable')) {
                    stream.write(segment[0][1].toUpperCase());
                } else {
                    throw 'Unsupported segment: ' + JSON.stringify(segment);
                }
            })
            stream.write('\n');
        })
    });
}
