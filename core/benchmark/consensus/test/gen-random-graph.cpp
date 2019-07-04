#include <vector>
#include <ctime>
#include <cstdlib>
#include <set>
#include <fstream>
#include <cstring>
#include <unistd.h>

const int MAXN = 100000;
const int MAXM = 5;

int N = 10000;
int ALPHA_NUM = 2;
int ALPHA_DEN = 3;
int BETA = 150;
int HEAVY_BLOCK_RATIO = 10;
int M = 3;
int MIN_GAP = 2;
int MAX_GAP = 30;
int ERA_BLOCK_COUNT = 50000;
std::vector<int> groups[MAXM];
std::vector<int> refs[MAXN + 1], children[MAXN + 1];
int local_clock[MAXN + 1][MAXM];
int current_clock[MAXM];
int parent[MAXN + 1];
int height[MAXN + 1], era_block[MAXN + 1];
int block_group[MAXN + 1], block_gidx[MAXN + 1];
int is_valid[MAXN + 1], is_stable[MAXN + 1], is_adaptive[MAXN + 1];
int weight[MAXN + 1];

int subtree_weight[MAXN + 1], subtree_stable_weight[MAXN + 1];
int subtree_inclusive_weight[MAXN + 1];
int past_era_weight[MAXN + 1];
bool consider[MAXN + 1];

bool should_consider(int v, int g) {
    if (v == 0) return true;
    int sub_g = block_group[v];
    if (block_gidx[v] > current_clock[sub_g]) return false;
    return true;
}

void mark_consider(int v, int g) {
    if (!should_consider(v, g)) return;
    consider[v] = true;
    for (int i = 0; i < children[v].size(); i++) {
        mark_consider(children[v][i], g);
    }
}

void compute_subtree(int v) {
    if (!consider[v]) {
        subtree_weight[v] = 0;
        subtree_stable_weight[v] = 0;
        subtree_inclusive_weight[v] = 0;
        return;
    }
    int sum = weight[v];
    int sums = weight[v];
    int sumi = weight[v];
    if (!is_stable[v])
        sums = 0;
    for (int i = 0; i < children[v].size(); i++) {
        compute_subtree(children[v][i]);
        sum += subtree_weight[children[v][i]];
        sums += subtree_stable_weight[children[v][i]];
        sumi += subtree_inclusive_weight[children[v][i]];
    }
    if (is_valid[v]) {
        subtree_weight[v] = sum;
        subtree_stable_weight[v] = sums;
    } else {
        subtree_weight[v] = 0;
        subtree_stable_weight[v] = 0;
    }
    subtree_inclusive_weight[v] = sumi;
}

void process(int n, int g) {
    memset(subtree_weight, 0, sizeof(subtree_weight));
    memset(subtree_inclusive_weight, 0, sizeof(subtree_inclusive_weight));
    memset(subtree_stable_weight, 0, sizeof(subtree_stable_weight));
    memset(consider, 0, sizeof(consider));
    mark_consider(0, g);
    compute_subtree(0);

    int last = -1;
    int current = 0;
    is_stable[n] = 1;
    std::vector<std::pair<int, int> > tmp;
    tmp.clear();
    // fprintf(stderr, "Process %d\n", n);
    while (true) {
        int largest_child = -1;
        int largest_weight = -1;
        for (int i = 0; i < children[current].size(); i++)
            if (consider[children[current][i]] && is_valid[children[current][i]] && subtree_weight[children[current][i]] > largest_weight) {
                largest_child = children[current][i];
                largest_weight = subtree_weight[children[current][i]];
            }
        // We want to avoid to have equal weights!!!
        int cnt = 0;
        for (int i = 0; i < children[current].size(); i++)
            if (consider[children[current][i]] && is_valid[children[current][i]] && subtree_weight[children[current][i]] == largest_weight) {
                cnt ++;
            }
        if (cnt > 1) {
            //fprintf(stderr, "current %d weight %d\n", current, largest_weight);
            parent[n] = -1;
            return;
        }
        if (largest_child == -1) break;
        last = current;
        current = largest_child;

        tmp.push_back(std::make_pair(last, current));
    }

    int parent_height = height[current];
    int era_height = parent_height / ERA_BLOCK_COUNT * ERA_BLOCK_COUNT;
    int era_block;
    if (era_height == 0) {
        era_block = 0;
    } else {
        era_block = tmp[era_height - 1].second;
    }
    int tot_weight = subtree_weight[era_block];

    for (int i = era_height; i < tmp.size(); i++) {
        int last = tmp[i].first;
        int current = tmp[i].second;
        int past_e_weight = past_era_weight[last];
        if (height[last] % ERA_BLOCK_COUNT == 0) {
            past_e_weight = 0;
        }
        int g = tot_weight - past_e_weight - weight[last];
        int f = subtree_weight[current];
        if (g > BETA && f * ALPHA_DEN - g * ALPHA_NUM < 0) {
            // fprintf(stderr, "%d %d %d %d\n", last, current, g, f);
            is_stable[n] = 0;
            break;
        }
    }

    is_adaptive[n] = 0;
    if (!is_stable[n]) {
        for (int i = era_height; i < tmp.size(); i++) {
            int px = tmp[i].first;
            int x = tmp[i].second;
            // fprintf(stderr, "%d %d %d %d\n", x, px, subtree_stable_weight[x], subtree_weight[px]);
            if (subtree_weight[px] > BETA &&
                subtree_stable_weight[x] * ALPHA_DEN - subtree_weight[px] * ALPHA_NUM < 0) {
                is_adaptive[n] = 1;
                break;
            }
        }
    }

    int two_era_height = era_height;
    if (two_era_height >= ERA_BLOCK_COUNT)
        two_era_height -= ERA_BLOCK_COUNT;
    if (!is_adaptive[n]) {
        for (int i = two_era_height; i < era_height && i < tmp.size(); i++) {
            int px = tmp[i].first;
            int x = tmp[i].second;
            if (subtree_inclusive_weight[px] > BETA &&
                subtree_inclusive_weight[x] * ALPHA_DEN - subtree_inclusive_weight[px] * ALPHA_NUM < 0) {
                is_adaptive[n] = 1;
                break;
            }
        }
    }

    parent[n] = current;
    past_era_weight[n] = tot_weight;
    if (is_adaptive[n]) {
        int x = rand() % HEAVY_BLOCK_RATIO;
        if (x == 0)
            weight[n] = HEAVY_BLOCK_RATIO;
        else
            weight[n] = 0;
    } else {
        weight[n] = 1;
    }

}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        N = atoi(argv[1]);
    }
    if (argc > 5) {
        ALPHA_NUM = atoi(argv[2]);
        ALPHA_DEN = atoi(argv[3]);
        BETA = atoi(argv[4]);
        HEAVY_BLOCK_RATIO = atoi(argv[5]);
    }
    if (argc > 6)
        ERA_BLOCK_COUNT = atoi(argv[6]);
    if (argc > 7) {
        MIN_GAP = atoi(argv[7]);
        MAX_GAP = atoi(argv[8]);
    }

    // Initialize genesis
    refs[0].clear();
    children[0].clear();
    parent[0] = -1;
    is_valid[0] = 1;
    is_stable[0] = 1;
    is_adaptive[0] = 0;
    block_group[0] = -1;
    block_gidx[0] = -1;
    weight[0] = 1;
    past_era_weight[0] = 0;
    height[0] = 0;
    era_block[0] = 0;

    unsigned seed = (unsigned) time(NULL) * getpid();
    // unsigned seed = 448648640;
    srand( seed );
    fprintf(stdout, "Random Seed: %u\n", seed);

    // Initialize the first M blocks for each branch
    for (int i = 1; i <= M; i++) {
        refs[i].clear();
        refs[i].push_back(0);
        children[i].clear();
        children[0].push_back(i);
        parent[i] = 0;
        is_valid[i] = 1;
        is_stable[i] = 1;
        groups[i - 1].push_back(0);
        groups[i - 1].push_back(i);
        for (int j = 0; j < M; j++)
            local_clock[i][j] = 0;

        block_group[i] = i - 1;
        block_gidx[i] = 1;
        past_era_weight[i] = 1;
        is_adaptive[i] = 0;
        weight[i] = 1;
        height[i] = 1;
        era_block[i] = 0;
    }

    // Randomly generate the remaining blocks
    for (int i = M + 1; i <= N; i++) {
        int g;
        do {
            g = rand() % M;
            int last_bidx = groups[g][groups[g].size() - 1];
            for (int j = 0; j < M; j++)
                current_clock[j] = local_clock[last_bidx][j];
            std::vector<int> tmp;
            tmp.clear();
            for (int j = 0; j < M; j++) {
                if (j == g) continue;
                if (groups[j].size() - 1 - current_clock[j] < MIN_GAP)
                    continue;
                if (groups[j].size() - 1 - current_clock[j] > MAX_GAP) {
                    tmp.push_back(groups[j][groups[j].size() - 1 - MAX_GAP]);
                } else {
                    int step = rand() % 3;
                    if (step > 0) {
                        tmp.push_back(groups[j][current_clock[j] + step]);
                    }
                }
            }
            tmp.push_back(last_bidx);
            sort(tmp.begin(), tmp.end());
            refs[i].clear();
            for (int j = tmp.size() - 1; j >= 0; j--) {
                int bidx = tmp[j];
                int gj = block_group[bidx];
                if (current_clock[gj] < block_gidx[bidx]) {
                    refs[i].push_back(bidx);
                    current_clock[gj] = block_gidx[bidx];
                    for (int k = 0; k < M; k++)
                        if (current_clock[k] < local_clock[bidx][k])
                            current_clock[k] = local_clock[bidx][k];
                }
            }
            process(i, g);
        } while (parent[i] == -1);

        is_valid[i] = 1;

        if (rand() % 4 == 0) {
            int x = -1;
            for (int j = 0; j < refs[i].size(); j++)
                if ((refs[i][j] != parent[i]) && (era_block[refs[i][j]] == era_block[parent[i]]) &&
                    (height[parent[i]] % ERA_BLOCK_COUNT != 0) && (height[refs[i][j]] % ERA_BLOCK_COUNT != 0)) {
                    x = refs[i][j];
                    break;
                }
            if (x != -1) {
                parent[i] = x;
                is_valid[i] = 0;
                weight[i] = 1;
            }
        }

        height[i] = height[parent[i]] + 1;
        if (height[i] % ERA_BLOCK_COUNT == 1) {
            era_block[i] = parent[i];
        } else {
            era_block[i] = era_block[parent[i]];
        }

        for (int j = 0; j < M; j++)
            local_clock[i][j] = current_clock[j];

        /*fprintf(stderr, "i = %d\n", i);
        fprintf(stderr, "g %d\n", g);
        for (int j = 0; j < M; j++)
            fprintf(stderr, "%d %lu %d\n", j, groups[j].size(), current_clock[j]);*/

        groups[g].push_back(i);
        children[parent[i]].push_back(i);

        block_group[i] = g;
        block_gidx[i] = groups[g].size() - 1;
    }


    std::ofstream fout;
    fout.open("rand.in", std::ios::out);
    fout << ALPHA_NUM << " " << ALPHA_DEN << " " << BETA << " " << HEAVY_BLOCK_RATIO << " " << ERA_BLOCK_COUNT << "\n";
    for (int i = 1; i <=N; i++) {
        fout << is_valid[i] << " " << is_stable[i] << " " << is_adaptive[i] << " "
             << ((weight[i] < 1) ? 1 : weight[i])
             << " " << parent[i];
        for (int j = 0; j < refs[i].size(); j++)
            if (refs[i][j] != parent[i])
                fout << " " << refs[i][j];
        fout << "\n";
    }
    fout.close();
}
