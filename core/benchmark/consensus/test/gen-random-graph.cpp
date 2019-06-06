#include <vector>
#include <ctime>
#include <cstdlib>
#include <set>
#include <fstream>
#include <cstring>
#include <unistd.h>

const int N = 10000;
const int M = 3;
const int MIN_GAP = 2;
const int MAX_GAP = 30;
std::vector<int> groups[M];
std::vector<int> refs[N + 1], children[N + 1];
int local_clock[N + 1][M];
int current_clock[M];
int parent[N + 1];
int block_group[N + 1], block_gidx[N + 1];
int is_valid[N + 1];

int subtree_weight[N + 1];
bool consider[N + 1];

bool should_consider(int v, int g) {
    if (v == 0) return true;
    if (!is_valid[v]) return false;
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
        return;
    }
    int sum = 1;
    for (int i = 0; i < children[v].size(); i++) {
        compute_subtree(children[v][i]);
        sum += subtree_weight[children[v][i]];
    }
    subtree_weight[v] = sum;
}

int find_parent(int n, int g) {
    memset(subtree_weight, 0, sizeof(subtree_weight));
    memset(consider, 0, sizeof(consider));
    mark_consider(0, g);
    compute_subtree(0);

    int current = 0;
    while (true) {
        int largest_child = -1;
        int largest_weight = -1;
        for (int i = 0; i < children[current].size(); i++)
            if (consider[children[current][i]] && subtree_weight[children[current][i]] > largest_weight) {
                largest_child = children[current][i];
                largest_weight = subtree_weight[children[current][i]];
            }
        // We want to avoid to have equal weights!!!
        int cnt = 0;
        for (int i = 0; i < children[current].size(); i++)
            if (consider[children[current][i]] && subtree_weight[children[current][i]] == largest_weight) {
                cnt ++;
            }
        if (cnt > 1) {
            //fprintf(stderr, "current %d weight %d\n", current, largest_weight);
            return -1;
        }
        if (largest_child == -1) break;
        current = largest_child;
    }
    return current;
}

int main() {
    // Initialize genesis
    refs[0].clear();
    children[0].clear();
    parent[0] = -1;
    is_valid[0] = 1;
    block_group[0] = -1;
    block_gidx[0] = -1;

    unsigned seed = (unsigned) time(NULL) * getpid();
    // unsigned seed = 1497907772;
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
        groups[i - 1].push_back(0);
        groups[i - 1].push_back(i);
        for (int j = 0; j < M; j++)
            local_clock[i][j] = 0;

        block_group[i] = i - 1;
        block_gidx[i] = 1;
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
            // refs[i].clear();
            for (int j = 0; j < M; j++) {
                if (j == g) continue;
                if (groups[j].size() - 1 - current_clock[j] < MIN_GAP)
                    continue;
                if (groups[j].size() - 1 - current_clock[j] > MAX_GAP) {
                    tmp.push_back(groups[j][groups[j].size() - 1 - MAX_GAP]);
                    // refs[i].push_back(groups[j][tips_idx[g][j]]);
                } else {
                    int step = rand() % 3;
                    if (step > 0) {
                        // tips_idx[g][j] += step;
                        tmp.push_back(groups[j][current_clock[j] + step]);
                        // refs[i].push_back(groups[j][tips_idx[g][j]]);
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
            parent[i] = find_parent(i, g);
        } while (parent[i] == -1);

        is_valid[i] = 1;

        if (rand() % 4 == 0) {
            int x = -1;
            for (int j = 0; j < refs[i].size(); j++)
                if (refs[i][j] != parent[i]) {
                    x = refs[i][j];
                    break;
                }
            if (x != -1) {
                parent[i] = x;
                is_valid[i] = 0;
            }
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
    for (int i = 1; i <=N; i++) {
        fout << is_valid[i] << " " << parent[i];
        for (int j = 0; j < refs[i].size(); j++)
            if (refs[i][j] != parent[i])
                fout << " " << refs[i][j];
        fout << "\n";
    }
    fout.close();
}