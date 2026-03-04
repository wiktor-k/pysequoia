const execSync = require("child_process").execSync;
const fs = require("fs");

const jobs = [];

const getMetadata = (attributes, key) => attributes
    .filter(attribute => 'metadata' in attribute)
    .flatMap(attribute => {
        let meta = attribute.metadata;
        let metaKey = meta[0];
        if (metaKey === key) {
            return meta.slice(1);
        } else {
            return [];
        }
    });

const getRecipePackages = (recipes, name) => {
    const recipe = recipes[name];
    const direct = getMetadata(recipe.attributes, 'pacman');
    const indirectDeps = recipe.body
        .filter(item => String(item[0]).startsWith('just '))
        .flatMap(item => item[0].split(' '))
        .filter(item => item !== 'just' && !item.startsWith('--'));
    direct.push(...indirectDeps.flatMap(dep => getRecipePackages(recipes, dep)));
    return direct;
}

for (const file of fs
    .readdirSync(".")
    .filter((file) => file === ".justfile" || file.endsWith(".just"))) {
    const justfile = JSON.parse(
        execSync(`just --justfile ${file} --dump --dump-format=json`, {
            encoding: "utf-8",
        }),
    );

    Object.values(justfile.recipes)
        .filter((recipe) =>
            recipe.attributes.some((attribute) => attribute.group == "ci"),
        )
        .forEach((recipe) => {
            let pacman = getRecipePackages(justfile.recipes, recipe.name);
            const packages = ['just'];
            if (pacman) {
                packages.push(...pacman);
            }

            const job = {
                packages: packages.join(' '),
                name: recipe.name,
                file,
                doc: recipe.doc,
            };

            jobs.push(job);
        });
}

fs.appendFileSync(
    process.env.GITHUB_OUTPUT,
    `jobs=` + JSON.stringify({ jobs }),
);
