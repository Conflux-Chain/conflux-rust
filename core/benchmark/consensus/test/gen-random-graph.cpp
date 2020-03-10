#include <vector>
#include <ctime>
#include <cstdlib>
#include <set>
#include <fstream>
#include <cstring>
#include <unistd.h>

const int MAXN = 100000;
const int MAXM = 5;
const int LOGN = 15;

int N = 10000;
int TIMER_RATIO = 50;
int TIMER_BETA = 20;
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
int p_table[MAXN + 1][LOGN];
int height[MAXN + 1];
int block_group[MAXN + 1], block_gidx[MAXN + 1];
int is_valid[MAXN + 1], is_timer[MAXN + 1], is_adaptive[MAXN + 1];
int weight[MAXN + 1];
int longest_timer_weight[MAXN + 1], last_timer[MAXN + 1];

int subtree_weight[MAXN + 1];
int is_timer_chain[MAXN + 1];
int past_timer[MAXN + 1];
bool consider[MAXN + 1];

int compute_lca(int a, int b) {
    if (height[a] < height[b])
        return compute_lca(b, a);
    int x = height[a] - height[b];
    int a1 = a;
    for (int i = LOGN - 1; i >=0; i--) {
        if ((x & (1 << i)) != 0)
            a1 = p_table[a1][i];
    }
    if (a1 == b)
        return a1;
    int b1 = b;
    for (int i = LOGN - 1; i >= 0; i--) {
        if (p_table[a1][i] != p_table[b1][i]) {
            a1 = p_table[a1][i];
            b1 = p_table[b1][i];
        }
    }
    return parent[a1];
}

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
        return;
    }
    int sum = weight[v];
    for (int i = 0; i < children[v].size(); i++) {
        compute_subtree(children[v][i]);
        sum += subtree_weight[children[v][i]];
    }
    subtree_weight[v] = sum;
}

int get_past_timer(int v) {
    if (past_timer[v] != -1) {
        return past_timer[v];
    }
    past_timer[v] = 0;
    for (int i = 0; i < refs[v].size(); i++) {
        int res = get_past_timer(refs[v][i]);
        if (is_timer_chain[refs[v][i]] && is_valid[refs[v][i]]) {
            res += 1;
        }
        if (past_timer[v] < res) {
            past_timer[v] = res;
        }
    }
    return past_timer[v];
}

void process(int n, int g) {
    memset(subtree_weight, 0, sizeof(subtree_weight));
    memset(is_timer_chain, 0, sizeof(is_timer_chain));
    memset(past_timer, -1, sizeof(past_timer));
    memset(consider, 0, sizeof(consider));
    mark_consider(0, g);
    compute_subtree(0);

    int longest_weight = -1;
    int best_last_timer = -1;
    for (int i = 0; i < refs[n].size(); i++) {
        int pred = refs[n][i];
        int w = longest_timer_weight[pred];
        if (is_timer[pred] && is_valid[pred]) w += 1;
        if (w > longest_weight) {
            longest_weight = w;
            if (is_timer[pred] && is_valid[pred])
                best_last_timer = pred;
            else
                best_last_timer = last_timer[pred];
        }
    }
    // Avoid same timer chain length with different header
    for (int i = 0; i < refs[n].size(); i++) {
        int pred = refs[n][i];
        int w = longest_timer_weight[pred];
        if (is_timer[pred] && is_valid[pred]) w += 1;
        if (w == longest_weight) {
            longest_weight = w;
            if (is_timer[pred] && is_valid[pred]) {
                if (pred != best_last_timer) {
                    parent[n] = -1;
                    return;
                }
            }
            else {
                if (last_timer[pred] != best_last_timer) {
                    parent[n] = -1;
                    return;
                }
            }
        }
    }
    longest_timer_weight[n] = longest_weight;
    last_timer[n] = best_last_timer;
    std::vector<int> timer_chain_vec;
    timer_chain_vec.clear();

    int current = last_timer[n];
    while (current != -1) {
        is_timer_chain[current] = 1;
        timer_chain_vec.push_back(current);
        current = last_timer[current];
    }
    int best_timer = timer_chain_vec.size();

    // Compute the force confirm position
    int force_confirm = 0;
    if (timer_chain_vec.size() > TIMER_BETA) {
        for (int i = TIMER_BETA; i < timer_chain_vec.size() - TIMER_BETA + 1; i++) {
            int lca = timer_chain_vec[i];
            for (int j = i + 1; j < i + TIMER_BETA; j++)
                lca = compute_lca(lca, timer_chain_vec[j]);
            // Because we are doing it in the reverse way, we will prioritize old ones, it includes equal sign here.
            if (height[lca] >= height[force_confirm])
                force_confirm = lca;
        }
    }

    int last = -1;
    current = force_confirm;
    std::vector<std::pair<int, int> > tmp;
    tmp.clear();
    // fprintf(stderr, "Process %d\n", n);
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
            parent[n] = -1;
            return;
        }
        if (largest_child == -1) break;
        last = current;
        current = largest_child;

        tmp.push_back(std::make_pair(last, current));
    }

    int parent_height = height[current];

    is_adaptive[n] = 0;
    for (int i = 0; i < tmp.size(); i++) {
        int last = tmp[i].first;
        int current = tmp[i].second;
        int current_timer = get_past_timer(current);
        assert(current_timer <= best_timer);
        if (best_timer - current_timer >= TIMER_BETA)
            if (2 * subtree_weight[current] - subtree_weight[last] + weight[last] < BETA) {
                is_adaptive[n] = 1;
                break;
            }
    }

    parent[n] = current;
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
        TIMER_RATIO = atoi(argv[2]);
        TIMER_BETA = atoi(argv[3]);
        BETA = atoi(argv[4]);
        HEAVY_BLOCK_RATIO = atoi(argv[5]);
    }
    if (argc > 6)
        ERA_BLOCK_COUNT = atoi(argv[6]);
    if (argc > 7) {
        MIN_GAP = atoi(argv[7]);
        MAX_GAP = atoi(argv[8]);
    }

    unsigned seed;
    char* seed_env = getenv("SEED");
    if (seed_env != NULL)
        seed = atoi(seed_env);
    else
        seed = (unsigned) time(NULL) * getpid();
    // unsigned seed = 448648640;
    srand( seed );
    fprintf(stdout, "Random Seed: %u\n", seed);

back_track:

    // Initialize genesis
    refs[0].clear();
    children[0].clear();
    parent[0] = -1;
    memset(p_table, -1, sizeof(p_table));
    is_valid[0] = 1;
    is_timer[0] = 0;
    is_adaptive[0] = 0;
    block_group[0] = -1;
    block_gidx[0] = -1;
    weight[0] = 1;
    height[0] = 0;
    longest_timer_weight[0] = 0;
    last_timer[0] = -1;

    // Initialize the first M blocks for each branch
    for (int i = 1; i <= M; i++) {
        refs[i].clear();
        refs[i].push_back(0);
        children[i].clear();
        children[0].push_back(i);
        parent[i] = 0;
        p_table[i][0] = 0;
        for (int j = 1; j < LOGN; j++)
            p_table[i][j] = -1;
        is_valid[i] = 1;
        is_timer[i] = 0;
        groups[i - 1].clear();
        groups[i - 1].push_back(0);
        groups[i - 1].push_back(i);
        for (int j = 0; j < M; j++)
            local_clock[i][j] = 0;

        block_group[i] = i - 1;
        block_gidx[i] = 1;
        is_adaptive[i] = 0;
        weight[i] = 1;
        height[i] = 1;

        longest_timer_weight[i] = 0;
        last_timer[i] = -1;
    }

    // Randomly generate the remaining blocks
    for (int i = M + 1; i <= N; i++) {
        int g;
        int retry_cnt = 0;
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
            retry_cnt ++;
        } while ((parent[i] == -1) && (retry_cnt < 100));
        children[i].clear();

        if (retry_cnt >= 100) {
            fprintf(stdout, "Back Tracking...\n");
            goto back_track;
        }

        is_valid[i] = 1;

        if (rand() % 4 == 0) {
            int x = -1;
            for (int j = 0; j < refs[i].size(); j++)
                if ((refs[i][j] != parent[i]) &&
                    (height[parent[i]] % ERA_BLOCK_COUNT != 0) && (height[refs[i][j]] % ERA_BLOCK_COUNT != 0)) {
                    x = refs[i][j];
                    break;
                }
            if (x != -1) {
                parent[i] = x;
                is_valid[i] = 0;
            }
        }
        p_table[i][0] = parent[i];
        for (int j = 1; j < LOGN; j++)
            if (p_table[i][j - 1] == -1)
                p_table[i][j] = -1;
            else
                p_table[i][j] = p_table[p_table[i][j-1]][j-1];

        if (weight[i] >= TIMER_RATIO) {
            is_timer[i] = 1;
        } else {
            if (rand() % TIMER_RATIO == 0) {
                is_timer[i] = 1;
            }
        }

        height[i] = height[parent[i]] + 1;

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
    fout << TIMER_RATIO << " " << TIMER_BETA << " " << BETA << " " << HEAVY_BLOCK_RATIO << " " << ERA_BLOCK_COUNT << "\n";
    for (int i = 1; i <=N; i++) {
        int diff = 1;
        if (is_timer[i]) {
            diff = TIMER_RATIO;
        }
        if (weight[i] > 1 && HEAVY_BLOCK_RATIO > diff)
            diff = HEAVY_BLOCK_RATIO;
        fout << is_valid[i] << " " << is_timer[i] << " " << is_adaptive[i] << " "
             << diff
             << " " << parent[i];
        for (int j = 0; j < refs[i].size(); j++)
            if (refs[i][j] != parent[i])
                fout << " " << refs[i][j];
        fout << "\n";
    }
    fout.close();
}
