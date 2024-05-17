def read_folder(tree=None, current_path=""):
    """
    Prompts the user to enter paths to create a directory tree.
    Args:
        tree (dict): The current state of the tree being built.
        current_path (str): The current path in the tree.
    Returns:
        tree (dict): A dictionary representing the folder structure.
    """
    if tree is None:
        tree = {}

    while True:
        # Display the current tree structure
        print(tree_string(tree, current_path if current_path else "root"))

        # Prompt user for the path
        path = input("Enter the path to the directory (or leave blank to finish): ")

        # Exit condition
        if path == "":
            return tree

        # Check if the path is a file or directory
        if "." in path:
            tree[path] = None
        else:
            # Recursively read subdirectories
            if path not in tree:
                tree[path] = {}
            read_folder(tree[path], current_path + "/" + path if current_path else path)

def tree_string(tree, root_name, level=0, prefix=""):
    """
    Generates a string representation of a tree using └──, ├── and │ characters.
    Args:
        tree (dict): The tree structure to print.
        root_name (str): The name of the root folder.
        level (int): The current depth level in the tree.
        prefix (str): The prefix to prepend to each line of the tree.

    Returns:
        str: A string representation of the tree.
    """
    tree_str = ""
    if level == 0:
        tree_str += root_name + "\n"
    keys = list(tree.keys())
    for i, key in enumerate(keys):
        connector = "└── " if i == len(keys) - 1 else "├── "
        tree_str += prefix + connector + key + "\n"
        if tree[key] is not None:
            child_prefix = prefix + ("    " if i == len(keys) - 1 else "│   ")
            tree_str += tree_string(tree[key], root_name, level + 1, child_prefix)
    return tree_str

if __name__ == "__main__":
    print("Welcome to the Folder Tree Generator!")
    folder_name = input("Enter the name of the root folder: ")
    tree = read_folder(None, folder_name)
    print("\nFinal folder structure:")
    print(tree_string(tree, folder_name))
